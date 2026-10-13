from datetime import datetime, timedelta
from functools import wraps
from hashlib import sha256
import csv
import io
import os
import time
from collections import defaultdict

import click
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.types import TypeDecorator, Text
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///nfsu_placement.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["WTF_CSRF_TIME_LIMIT"] = 3600
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Field-level encryption. Set FIELD_ENCRYPTION_KEY to a persistent Fernet key
# for deployment; the derived development key is only for local demonstration.
def _fernet_key():
    configured = os.environ.get("FIELD_ENCRYPTION_KEY")
    if configured:
        return configured.encode("ascii")
    seed = os.environ.get("SECRET_KEY", "dev-only-change-this-secret").encode("utf-8")
    return __import__("base64").urlsafe_b64encode(sha256(seed + b"field-encryption-dev-key").digest())

fernet = Fernet(_fernet_key())

class EncryptedText(TypeDecorator):
    impl = Text
    cache_ok = True
    def process_bind_param(self, value, dialect):
        if value is None or value == "":
            return value
        return fernet.encrypt(str(value).encode("utf-8")).decode("ascii")
    def process_result_value(self, value, dialect):
        if value is None or value == "":
            return value
        try:
            return fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            # Allows legacy plaintext rows to be read during a local migration.
            return value

class EncryptedFloat(TypeDecorator):
    impl = Text
    cache_ok = True
    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return fernet.encrypt(str(float(value)).encode("ascii")).decode("ascii")
    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            return float(fernet.decrypt(value.encode("ascii")).decode("ascii"))
        except (InvalidToken, ValueError):
            return float(value)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cache-Control", "no-store")
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

PROGRAMMES = [
    "M.Tech. CS",
    "M.Tech. AIDS",
    "B.Tech.-M.Tech. CSE",
    "M.Sc. CS",
    "M.Sc. DFIS",
]
ROLES = ["placement_admin", "placement_officer", "course_coordinator", "recruiter"]
OFFER_TYPES = ["I", "F", "I+F"]


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(190), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="placement_officer")
    assigned_programme = db.Column(db.String(80), nullable=True)
    assigned_company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=False)


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    placement_id = db.Column(db.String(40), unique=True, nullable=False)
    full_name = db.Column(db.String(160), nullable=False)
    mobile = db.Column(EncryptedText())
    email = db.Column(db.String(190), nullable=False)
    programme = db.Column(db.String(80), nullable=False)
    batch_year = db.Column(db.Integer, nullable=False)
    registration_status = db.Column(db.String(30), default="registered", nullable=False)
    eligibility_status = db.Column(db.String(30), default="pending", nullable=False)
    placement_status = db.Column(db.String(40), default="unplaced", nullable=False)
    archived = db.Column(db.Boolean, default=False, nullable=False)
    archived_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(180), nullable=False)
    category = db.Column(db.String(4), nullable=False)  # A+, A, B, C


class Offer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey("student.id"), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=False)
    offer_type = db.Column(db.String(3), nullable=False)  # I, F, I+F
    stipend = db.Column(EncryptedFloat())
    stipend_period = db.Column(db.String(20))
    fte_ctc_lpa = db.Column(EncryptedFloat())
    ppo_status = db.Column(db.String(30), default="not_applicable", nullable=False)
    acceptance_status = db.Column(db.String(20), default="pending", nullable=False)
    joining_status = db.Column(db.String(20), default="pending", nullable=False)
    offer_date = db.Column(db.Date)
    deadline = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    student = db.relationship("Student", backref=db.backref("offers", lazy=True))
    company = db.relationship("Company", backref=db.backref("offers", lazy=True))


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_email = db.Column(db.String(190))
    action = db.Column(db.String(80), nullable=False)
    entity = db.Column(db.String(80), nullable=False)
    entity_id = db.Column(db.String(80))
    details = db.Column(db.Text)
    previous_hash = db.Column(db.String(64), nullable=True)
    event_hash = db.Column(db.String(64), nullable=True, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


ROLE_PERMISSIONS = {
    "placement_admin": {"dashboard:view", "students:view", "students:create", "students:update", "students:archive", "companies:view", "companies:create", "offers:view", "offers:create", "exports:create"},
    "placement_officer": {"dashboard:view", "students:view", "students:create", "students:update", "students:archive", "companies:view", "companies:create", "offers:view", "offers:create", "exports:create"},
    "course_coordinator": {"dashboard:view", "students:view", "students:create", "students:update"},
    "recruiter": {"offers:view"},
}


def has_permission(user, permission):
    return bool(user and user.active and permission in ROLE_PERMISSIONS.get(user.role, set()))


def permission_required(permission):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect(url_for("login", next=request.path))
            if not has_permission(user, permission):
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect(url_for("login"))
            if user.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def audit(action, entity, entity_id=None, details=""):
    user = current_user()
    previous = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev_hash = previous.event_hash if previous else "GENESIS"
    created = datetime.utcnow()
    actor = user.email if user else "system"
    material = "|".join([prev_hash or "", actor, action, entity, str(entity_id or ""), details, created.isoformat()])
    event_hash = sha256(material.encode("utf-8")).hexdigest()
    db.session.add(AuditLog(
        actor_email=actor, action=action, entity=entity,
        entity_id=str(entity_id) if entity_id else None, details=details,
        previous_hash=prev_hash, event_hash=event_hash, created_at=created
    ))


def audit_access(entity, entity_id=None):
    # Log access without recording the sensitive field values themselves.
    audit("read", entity, entity_id, f"path={request.path}; method={request.method}")


def evaluate_placement_policy(student, new_company_category, new_offer_type, new_ctc_lpa=None):
    """
    Starter interpretation of the supplied event statement.
    Always review final rules against the official complete policy before presenting as authoritative.
    """
    reasons = []
    if student.registration_status != "registered":
        reasons.append("Student is not currently registered for placement.")
    if student.eligibility_status != "eligible":
        reasons.append("Student eligibility is not verified as eligible.")

    existing_offers = student.offers
    # Offer-type restrictions from the problem statement.
    for offer in existing_offers:
        if offer.offer_type == "I+F":
            reasons.append("Existing I+F selection blocks participation in other I, F, or I+F roles.")
            break
        if offer.offer_type == "I" and new_offer_type == "I":
            reasons.append("Existing internship-only selection blocks another I role.")
            break
        if offer.offer_type == "F" and new_offer_type == "F":
            reasons.append("Existing FTE-only selection blocks another F role.")
            break

    # Category/CTC switching checks. The statement's A boundary overlaps at 16 LPA
    # and B boundary overlaps at 10 LPA, so this prototype uses explicit categories
    # supplied by the company record and flags unclear/missing salary details for review.
    for offer in existing_offers:
        old_category = offer.company.category
        old_ctc = offer.fte_ctc_lpa
        if old_category == "A+":
            reasons.append("Existing A+ selection: no further placement participation.")
            break
        if old_category == "A" and new_company_category != "A+":
            reasons.append("Existing A-category selection: switching is allowed only to A+.")
            break
        if old_category == "B":
            if new_ctc_lpa is None or old_ctc is None:
                reasons.append("B-category switching requires verified existing and new FTE CTC; manual review needed.")
                break
            if new_ctc_lpa < 1.5 * old_ctc:
                reasons.append(f"New CTC must be at least 1.5× the existing CTC ({1.5 * old_ctc:.2f} LPA).")
                break
        # C category: higher-category opportunities are allowed as described in the policy;
        # detailed edge cases require the complete official guideline.
    return {"allowed": not reasons, "reasons": reasons or ["No blocking rule found in this starter check."]}


@app.context_processor
def inject_globals():
    return {"current_user": current_user(), "programmes": PROGRAMMES}


@app.route("/")
@permission_required("dashboard:view")
def home():
    audit_access("dashboard")
    db.session.commit()
    total = Student.query.filter_by(archived=False).count()
    eligible = Student.query.filter_by(archived=False, eligibility_status="eligible").count()
    placed_ids = db.session.query(Offer.student_id).filter_by(acceptance_status="accepted").distinct().all()
    placed = len(placed_ids)
    pending = Offer.query.filter_by(acceptance_status="pending").count()
    recent = Student.query.filter_by(archived=False).order_by(Student.created_at.desc()).limit(8).all()
    return render_template("dashboard.html", total=total, eligible=eligible, placed=placed, pending=pending, recent=recent)


# In-memory throttling is useful for a single-process demo; use Redis-backed
# rate limiting behind a production WSGI server for deployment.
_login_attempts = defaultdict(list)

def login_limited(ip):
    now = time.time()
    recent = [t for t in _login_attempts[ip] if now - t < 300]
    _login_attempts[ip] = recent
    return len(recent) >= 8

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "unknown"
    if request.method == "POST":
        if login_limited(ip):
            flash("Too many login attempts. Wait five minutes and try again.", "error")
            return render_template("login.html"), 429
        _login_attempts[ip].append(time.time())
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email, active=True).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session.permanent = True
            session["user_id"] = user.id
            audit("login", "user", user.id, "successful login")
            db.session.commit()
            flash("Welcome back.", "success")
            return redirect(url_for("home"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", "user", current_user().id, "logout")
    db.session.commit()
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/students")
@permission_required("students:view")
def students():
    audit_access("student_directory")
    db.session.commit()
    user = current_user()
    query = Student.query.filter_by(archived=False)
    if user.role == "course_coordinator":
        if not user.assigned_programme:
            abort(403, description="Coordinator has no assigned programme.")
        query = query.filter_by(programme=user.assigned_programme)
    search = request.args.get("q", "").strip()
    programme = request.args.get("programme", "")
    if search:
        like = f"%{search}%"
        query = query.filter(db.or_(Student.full_name.ilike(like), Student.placement_id.ilike(like)))
    if programme in PROGRAMMES:
        query = query.filter_by(programme=programme)
    records = query.order_by(Student.full_name.asc()).all()
    return render_template("students.html", records=records, search=search, selected_programme=programme)


@app.route("/students/new", methods=["GET", "POST"])
@permission_required("students:create")
def student_new():
    if request.method == "POST":
        placement_id = request.form.get("placement_id", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        programme = request.form.get("programme", "")
        try:
            batch_year = int(request.form.get("batch_year", ""))
        except ValueError:
            batch_year = 0
        user = current_user()
        if user.role == "course_coordinator" and programme != user.assigned_programme:
            abort(403)
        if not placement_id or not full_name or not email or programme not in PROGRAMMES or not 2000 <= batch_year <= 2100:
            flash("Please provide valid required student details.", "error")
            return render_template("student_form.html", student=None)
        if Student.query.filter_by(placement_id=placement_id).first():
            flash("Placement ID already exists.", "error")
            return render_template("student_form.html", student=None)
        student = Student(
            placement_id=placement_id, full_name=full_name, email=email,
            mobile=request.form.get("mobile", "").strip() or None,
            programme=programme, batch_year=batch_year,
            registration_status=request.form.get("registration_status", "registered"),
            eligibility_status=request.form.get("eligibility_status", "pending"),
        )
        db.session.add(student)
        db.session.flush()
        audit("create", "student", student.id, f"placement_id={placement_id}")
        db.session.commit()
        flash("Student added.", "success")
        return redirect(url_for("students"))
    return render_template("student_form.html", student=None)


@app.route("/students/<int:student_id>/edit", methods=["GET", "POST"])
@permission_required("students:update")
def student_edit(student_id):
    student = db.get_or_404(Student, student_id)
    user = current_user()
    if student.archived:
        abort(404)
    if user.role == "course_coordinator" and student.programme != user.assigned_programme:
        abort(403)
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        programme = request.form.get("programme", "")
        try:
            batch_year = int(request.form.get("batch_year", ""))
        except ValueError:
            batch_year = 0
        if not full_name or not email or programme not in PROGRAMMES or not 2000 <= batch_year <= 2100:
            flash("Please provide valid details.", "error")
            return render_template("student_form.html", student=student)
        before = f"name={student.full_name}; eligibility={student.eligibility_status}"
        student.full_name = full_name
        student.email = email
        student.mobile = request.form.get("mobile", "").strip() or None
        student.programme = programme
        student.batch_year = batch_year
        # Only authorized placement staff can change status; recruiters have no route access.
        if user.role != "course_coordinator":
            student.registration_status = request.form.get("registration_status", student.registration_status)
            student.eligibility_status = request.form.get("eligibility_status", student.eligibility_status)
        audit("update", "student", student.id, f"before[{before}] after[name={full_name}; eligibility={student.eligibility_status}]")
        db.session.commit()
        flash("Student updated.", "success")
        return redirect(url_for("students"))
    return render_template("student_form.html", student=student)


@app.route("/students/<int:student_id>/archive", methods=["POST"])
@permission_required("students:archive")
def student_archive(student_id):
    student = db.get_or_404(Student, student_id)
    student.archived = True
    student.archived_at = datetime.utcnow()
    audit("archive", "student", student.id, f"placement_id={student.placement_id}")
    db.session.commit()
    flash("Student archived; historical offers remain preserved.", "success")
    return redirect(url_for("students"))


@app.route("/companies")
@permission_required("companies:view")
def companies():
    audit_access("company_directory")
    db.session.commit()
    records = Company.query.order_by(Company.name.asc()).all()
    return render_template("companies.html", records=records)


@app.route("/companies/new", methods=["GET", "POST"])
@permission_required("companies:create")
def company_new():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "")
        if not name or category not in ["A+", "A", "B", "C"]:
            flash("Enter a company name and valid category.", "error")
            return render_template("company_form.html")
        company = Company(name=name, category=category)
        db.session.add(company)
        db.session.flush()
        audit("create", "company", company.id, f"name={name}; category={category}")
        db.session.commit()
        flash("Company added.", "success")
        return redirect(url_for("companies"))
    return render_template("company_form.html")


@app.route("/offers")
@permission_required("offers:view")
def offers():
    audit_access("offer_directory")
    db.session.commit()
    user = current_user()
    query = Offer.query
    if user.role == "recruiter":
        if not user.assigned_company_id:
            abort(403, description="Recruiter has no assigned company.")
        query = query.filter_by(company_id=user.assigned_company_id)
    records = query.order_by(Offer.created_at.desc()).all()
    return render_template("offers.html", records=records)


@app.route("/offers/new", methods=["GET", "POST"])
@permission_required("offers:create")
def offer_new():
    students_list = Student.query.filter_by(archived=False).order_by(Student.full_name).all()
    companies_list = Company.query.order_by(Company.name).all()
    result = None
    if request.method == "POST":
        student = db.session.get(Student, request.form.get("student_id", type=int))
        company = db.session.get(Company, request.form.get("company_id", type=int))
        offer_type = request.form.get("offer_type", "")
        try:
            ctc = float(request.form.get("fte_ctc_lpa", "").strip()) if request.form.get("fte_ctc_lpa", "").strip() else None
            stipend = float(request.form.get("stipend", "").strip()) if request.form.get("stipend", "").strip() else None
        except ValueError:
            ctc, stipend = -1, -1
        if not student or not company or offer_type not in OFFER_TYPES or (ctc is not None and ctc < 0) or (stipend is not None and stipend < 0):
            flash("Check student, company, offer type, stipend, and CTC values.", "error")
            return render_template("offer_form.html", students=students_list, companies=companies_list, result=None)
        result = evaluate_placement_policy(student, company.category, offer_type, ctc)
        if request.form.get("save_anyway") != "yes" and not result["allowed"]:
            flash("Policy check blocked this offer. Review the reasons below; authorized exceptions are not implemented in this starter.", "error")
            return render_template("offer_form.html", students=students_list, companies=companies_list, result=result)
        offer = Offer(
            student=student, company=company, offer_type=offer_type,
            fte_ctc_lpa=ctc, stipend=stipend,
            stipend_period=request.form.get("stipend_period") or None,
            ppo_status="pending" if offer_type == "I+F" else "not_applicable",
            acceptance_status="pending",
            deadline=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(offer)
        db.session.flush()
        audit("create", "offer", offer.id, f"student={student.placement_id}; company={company.name}; policy_allowed={result['allowed']}")
        db.session.commit()
        flash("Offer recorded.", "success")
        return redirect(url_for("offers"))
    return render_template("offer_form.html", students=students_list, companies=companies_list, result=result)


@app.cli.command("seed-demo")
def seed_demo():
    """Create schema and add fictional demo data plus a local demo admin."""
    db.create_all()
    admin = User.query.filter_by(email="admin@nfsu.local").first()
    if not admin:
        db.session.add(User(full_name="Demo Administrator", email="admin@nfsu.local",
                           password_hash=generate_password_hash("ChangeMe123!"), role="placement_admin"))
    if Student.query.count() == 0:
        examples = [
            Student(placement_id="DEMO-001", full_name="Aarav Shah", email="aarav@example.test",
                    programme="M.Tech. CS", batch_year=2027, registration_status="registered", eligibility_status="eligible"),
            Student(placement_id="DEMO-002", full_name="Isha Patel", email="isha@example.test",
                    programme="M.Sc. DFIS", batch_year=2027, registration_status="registered", eligibility_status="pending"),
            Student(placement_id="DEMO-003", full_name="Kabir Mehta", email="kabir@example.test",
                    programme="M.Tech. AIDS", batch_year=2027, registration_status="registered", eligibility_status="eligible"),
        ]
        db.session.add_all(examples)
    if Company.query.count() == 0:
        db.session.add_all([
            Company(name="Example Analytics", category="B"),
            Company(name="Example Secure Systems", category="A"),
            Company(name="Example AI Labs", category="A+"),
        ])
    db.session.commit()
    click.echo("Demo data ready. Login: admin@nfsu.local / ChangeMe123!")
    click.echo("Use fictional data only and change the demo password before sharing.")


@app.route("/exports/students.csv")
@permission_required("exports:create")
def export_students():
    audit_access("student_export")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Placement ID", "Full name", "Email", "Mobile", "Programme", "Batch", "Registration", "Eligibility", "Placement status"])
    query = Student.query.filter_by(archived=False)
    user = current_user()
    if user.role == "course_coordinator":
        if not user.assigned_programme:
            abort(403)
        query = query.filter_by(programme=user.assigned_programme)
    for s in query.order_by(Student.placement_id).all():
        writer.writerow([s.placement_id, s.full_name, s.email, s.mobile, s.programme, s.batch_year,
                         s.registration_status, s.eligibility_status, s.placement_status])
    audit("export", "students", None, f"csv export by role={user.role}; rows=filtered")
    db.session.commit()
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = 'attachment; filename="students_export.csv"'
    response.headers["Cache-Control"] = "no-store"
    return response


@app.cli.command("verify-audit")
def verify_audit():
    """Verify the audit hash chain from oldest to newest."""
    previous = "GENESIS"
    for row in AuditLog.query.order_by(AuditLog.id.asc()).all():
        if row.previous_hash != previous:
            raise click.ClickException(f"Audit chain broken at record {row.id}: previous hash mismatch")
        material = "|".join([previous or "", row.actor_email or "", row.action or "", row.entity or "",
                             str(row.entity_id or ""), row.details or "", row.created_at.isoformat()])
        expected = sha256(material.encode("utf-8")).hexdigest()
        if row.event_hash != expected:
            raise click.ClickException(f"Audit chain broken at record {row.id}: event hash mismatch")
        previous = row.event_hash
    click.echo("Audit hash chain verified.")


@app.cli.command("backup-encrypted")
@click.option("--output", default="backups/nfsu_placement.db.enc", show_default=True)
def backup_encrypted(output):
    """Create a Fernet-encrypted backup of the SQLite database."""
    from pathlib import Path
    db_uri = app.config["SQLALCHEMY_DATABASE_URI"]
    if not db_uri.startswith("sqlite:///"):
        raise click.ClickException("This backup command currently supports SQLite only.")
    db_path = db_uri.replace("sqlite:///", "", 1)
    if not os.path.isabs(db_path):
        db_path = os.path.join(app.instance_path, db_path)
    if not os.path.exists(db_path):
        raise click.ClickException(f"Database file not found: {db_path}")
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with open(db_path, "rb") as source:
        encrypted = fernet.encrypt(source.read())
    with open(output, "wb") as dest:
        dest.write(encrypted)
    click.echo(f"Encrypted backup written to {output}. Store the encryption key separately.")


@app.cli.command("restore-encrypted")
@click.argument("backup_path")
@click.option("--output", default="instance/nfsu_placement.db", show_default=True)
def restore_encrypted(backup_path, output):
    """Restore a Fernet-encrypted SQLite backup to a new file (does not overwrite automatically)."""
    if os.path.exists(output):
        raise click.ClickException(f"Output already exists: {output}. Choose a new path; never overwrite automatically.")
    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    try:
        with open(backup_path, "rb") as source:
            plain = fernet.decrypt(source.read())
    except (OSError, InvalidToken) as exc:
        raise click.ClickException("Backup could not be decrypted. Check the backup and FIELD_ENCRYPTION_KEY.") from exc
    with open(output, "wb") as dest:
        dest.write(plain)
    click.echo(f"Restored database to {output}. Verify it before switching the app to it.")


@app.cli.command("purge-archived")
@click.option("--older-than-days", default=730, show_default=True, type=int)
@click.option("--execute", is_flag=True, help="Actually delete records. Without this flag, only reports the count.")
def purge_archived(older_than_days, execute):
    """Retention helper: purge archived student records after the approved retention period."""
    cutoff = datetime.utcnow() - timedelta(days=older_than_days)
    query = Student.query.filter(Student.archived.is_(True), Student.archived_at.isnot(None), Student.archived_at < cutoff)
    count = query.count()
    if not execute:
        click.echo(f"DRY RUN: {count} archived student records are older than {older_than_days} days.")
        click.echo("Review institutional retention policy and run with --execute only after authorization.")
        return
    if not has_permission_for_cli_retention():
        raise click.ClickException("Set RETENTION_PURGE_APPROVED=1 after formal approval to execute.")
    ids = [s.id for s in query.all()]
    for sid in ids:
        # Preserve audit trail; offers referencing the student must be handled by policy first.
        if Offer.query.filter_by(student_id=sid).count():
            continue
        Student.query.filter_by(id=sid).delete()
    db.session.commit()
    click.echo(f"Purged eligible archived records without offers. Audit logs were preserved.")


def has_permission_for_cli_retention():
    return os.environ.get("RETENTION_PURGE_APPROVED") == "1"

# NFSU Secure Placement Management — Python Starter

## Features in this starter
- Flask web app and SQLite database (no MySQL setup required)
- Dashboard with live counts
- Student list, search, add, edit, archive
- Companies and offer tracking
- Server-side placement policy evaluation helper
- Password hashing and basic login scaffold
- Demo seed command using fictional data

## Setup (Windows)
1. Install Python 3.11+.
2. Extract this folder.
3. Open Command Prompt in this folder.
4. Run:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
5. Seed fictional demo data:
   ```bat
   flask --app app seed-demo
   ```
6. Run:
   ```bat
   flask --app app run --debug
   ```
7. Open http://127.0.0.1:5000

Demo login after seeding:
- Email: admin@nfsu.local
- Password: ChangeMe123!

## Important security note
This is a local event prototype, not production-ready. It uses a development secret by default and has no CSRF protection/MFA/rate limiting yet. Change the secret, add CSRF protection, configure secure cookies and HTTPS, and review policy interpretations before any real deployment. Use fictional data only.

\n## RBAC roles\n
- **placement_admin**: full prototype administration.
- **placement_officer**: manages students, companies, and offers.
- **course_coordinator**: limited to their assigned programme; cannot archive students or change eligibility/registration decisions.
- **recruiter**: cannot access the student directory; can view offers only for their assigned company. Offer creation is disabled.

Assign `assigned_programme` to a course coordinator and `assigned_company_id` to a recruiter through a trusted local admin script/shell. Existing SQLite databases created before these columns were added may need to be deleted and recreated for this prototype (the demo data will be reseeded).

RBAC is a prototype implementation, not production security. Still required: CSRF protection, login rate limiting, session timeout and secure cookie settings, HTTPS, field-level confidentiality, tamper-evident audit storage, encrypted backups, controlled exports, and retention procedures.


## Security controls added in this version
- CSRF protection via Flask-WTF for POST forms.
- HttpOnly and SameSite=Lax session cookies, 30-minute permanent-session lifetime, and configurable Secure cookie flag.
- Best-effort login throttling (in-memory; replace with shared Redis-backed limiter for multi-worker deployments).
- Field-level encryption for student email/mobile and offer stipend/CTC via Fernet.
- Hash-chained audit records and `verify-audit` command.
- Role-restricted CSV export with audit event and no-store response headers.
- Encrypted SQLite backup and non-overwriting restore commands.
- Retention dry-run command for archived students; actual purge requires explicit `RETENTION_PURGE_APPROVED=1` and skips records with offers.
- Server-side RBAC and programme/company scoping from the previous update.

## Required environment variables for deployment
Set a strong, unique `SECRET_KEY` and a stable `FIELD_ENCRYPTION_KEY`. Generate the Fernet key once:
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```
Keep these secrets outside source control and store backup keys separately. If the encryption key changes or is lost, encrypted contact/compensation fields and backups may become unreadable. `SESSION_COOKIE_SECURE=1` must be used behind HTTPS; do not set it for plain HTTP localhost or the browser will not send the session cookie.

## Commands
```bat
python -m flask --app app seed-demo
python -m flask --app app run --debug
python -m flask --app app verify-audit
python -m flask --app app backup-encrypted
python -m flask --app app restore-encrypted backups/nfsu_placement.db.enc --output instance/restored.db
python -m flask --app app purge-archived
```
For an approved purge only, set `RETENTION_PURGE_APPROVED=1` in the environment and explicitly pass `--execute`. Review retention requirements first.

## Important prototype limitations
- Existing SQLite databases need to be backed up and recreated for this schema change; encrypted type columns are not a transparent migration for existing plaintext rows.
- Login throttling is in-memory and does not work across multiple worker processes.
- HTTPS is a deployment/server configuration, not provided by the local Flask development server.
- Fernet field encryption protects selected fields, not the entire database file. Encrypted backups protect the backup file; protect the live database using encrypted disk/volume storage and access controls.
- Audit hash chaining detects edits/reordering when verified, but an attacker with database write access could recompute the chain. For stronger tamper evidence, forward logs to a separate append-only/remote logging system.
- Export currently covers student CSV only. Add separate role-reviewed offer exports before exposing salary exports.
- No MFA is included; it is optional in the statement. Production rollout still requires security review, tests, backup-restore drills, and policy approval.

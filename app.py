import json
import re
import socket
import sqlite3
import time
from collections import defaultdict
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask import abort
from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.datastructures import MultiDict

app = Flask(__name__)
import os
app.secret_key = os.environ.get("SECRET_KEY", "dev")
DATABASE = "stormcalls.db"
ADMIN_PASSWORD = "NXR420!yourmother"

# ==========================================================================
# Constants
# ==========================================================================

US_STATES = [
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA",
    "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD",
    "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ",
    "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC",
    "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
    "DC", "PR", "VI",
]

REGIONS = [
    "Gulf Coast", "Southeast", "Mid-Atlantic", "Northeast",
    "Midwest", "Great Plains", "Southwest", "West", "Pacific Northwest",
]

CLASSIFICATIONS = [
    ("JL", "Journeyman Lineman"),
    ("AL", "Apprentice Lineman"),
    ("GM", "Groundman"),
    ("OP", "Equipment Operator"),
    ("CS", "Cable Splicer"),
    ("ST", "Substation Technician"),
]

CONTRACTOR_TYPES = [
    "Line Construction", "Storm Restoration", "Transmission", "Distribution",
]

POST_TYPES_TIER1 = ["Official Call", "Update", "Advisory"]
POST_TYPES_TIER2 = ["Mobilization Notice", "Advisory"]

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.uk", "outlook.com", "hotmail.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "mail.com",
    "protonmail.com", "proton.me", "zoho.com", "yandex.com",
    "gmx.com", "gmx.net", "live.com", "msn.com",
    "comcast.net", "att.net", "verizon.net", "cox.net", "charter.net",
    "earthlink.net", "sbcglobal.net", "bellsouth.net",
}

FORBIDDEN_PATTERNS = [
    (r"send\s+(your|me|us)\s+(ticket|info|resume|details|number)", "Requesting worker information"),

]

TIER2_DISCLAIMER = (
    "All work must clear through the appropriate IBEW local. "
    "This platform does not dispatch or hire."
)
# ==========================================================================
# Database
# ==========================================================================


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS tier1_posters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            local_number TEXT NOT NULL,
            local_name TEXT,
            city TEXT,
            state TEXT,
            contact_email TEXT NOT NULL UNIQUE,
            contact_phone TEXT,
            verified INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS contractors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_legal_name TEXT NOT NULL,
            headquarters_state TEXT NOT NULL,
            company_website TEXT NOT NULL,
            company_email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            primary_contact_name TEXT NOT NULL,
            primary_contact_phone TEXT NOT NULL,
            contractor_type TEXT NOT NULL,
            states_of_operation TEXT NOT NULL,
            ibew_signatory INTEGER NOT NULL DEFAULT 0,
            clears_through_ibew INTEGER NOT NULL DEFAULT 0,
            locals_cleared_through TEXT,
            intent_mobilization INTEGER NOT NULL DEFAULT 0,
            intent_advisories INTEGER NOT NULL DEFAULT 0,
            ack_no_dispatch INTEGER NOT NULL DEFAULT 0,
            ack_clear_through_local INTEGER NOT NULL DEFAULT 0,
            ack_no_collect_info INTEGER NOT NULL DEFAULT 0,
            email_domain_validated INTEGER NOT NULL DEFAULT 0,
            website_resolves INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            admin_notes TEXT,
            revoked_at TIMESTAMP,
            revoked_by TEXT,
            revoked_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poster_type TEXT NOT NULL,
            poster_id INTEGER NOT NULL,
            poster_display_name TEXT NOT NULL,
            post_type TEXT NOT NULL,
            region TEXT NOT NULL,
            states TEXT NOT NULL,
            expected_start_window TEXT NOT NULL,
            classification_needed TEXT NOT NULL,
            clearing_locals TEXT NOT NULL,
            hall_contact TEXT,
            short_notes TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            details TEXT,
            performed_by TEXT NOT NULL,
            previous_status TEXT,
            new_status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Migrations for existing databases
    cursor = db.execute("PRAGMA table_info(contractors)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    for col, coldef in [
        ("revoked_at", "TIMESTAMP"),
        ("revoked_by", "TEXT"),
        ("revoked_reason", "TEXT"),
    ]:
        if col not in existing_cols:
            db.execute(f"ALTER TABLE contractors ADD COLUMN {col} {coldef}")

    cursor = db.execute("PRAGMA table_info(audit_log)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    for col, coldef in [
        ("previous_status", "TEXT"),
        ("new_status", "TEXT"),
    ]:
        if col not in existing_cols:
            db.execute(f"ALTER TABLE audit_log ADD COLUMN {col} {coldef}")
        # Migration for posts expiration
    cursor = db.execute("PRAGMA table_info(posts)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    if "expires_at" not in existing_cols:
        db.execute("ALTER TABLE posts ADD COLUMN expires_at TIMESTAMP")

    db.commit()
    db.close()

with app.app_context():
    init_db()



# ==========================================================================
# Helpers
# ==========================================================================

@app.template_filter("from_json")
def from_json_filter(value):
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []

import re
from markupsafe import Markup, escape

URL_RE = re.compile(r'(https?://[^\s<]+|www\.[^\s<]+)', re.IGNORECASE)

@app.template_filter("linkify")
def linkify(text):
    """Convert URLs in plain text into clickable links safely."""
    if not text:
        return ""
    safe = escape(text)

    def repl(match):
        url = match.group(0)
        href = url if url.lower().startswith("http") else f"https://{url}"
        return Markup(f'<a href="{href}" target="_blank" rel="noopener noreferrer">{url}</a>')

    return Markup(URL_RE.sub(repl, safe))

@app.context_processor
def inject_constants():
    return dict(
        US_STATES=US_STATES,
        REGIONS=REGIONS,
        CLASSIFICATIONS=CLASSIFICATIONS,
        CONTRACTOR_TYPES=CONTRACTOR_TYPES,
        POST_TYPES_TIER1=POST_TYPES_TIER1,
        POST_TYPES_TIER2=POST_TYPES_TIER2,
        TIER2_DISCLAIMER=TIER2_DISCLAIMER,
    )


def get_email_domain(email):
    if "@" not in email:
        return None
    return email.split("@")[1].lower().strip()


def get_website_domain(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain.split(":")[0]
    except Exception:
        return None


def domains_match(email_domain, website_domain):
    if not email_domain or not website_domain:
        return False
    return (
        email_domain == website_domain
        or email_domain.endswith("." + website_domain)
        or website_domain.endswith("." + email_domain)
    )


def domain_resolves(domain):
    try:
        socket.getaddrinfo(domain, 80, proto=socket.IPPROTO_TCP)
        return True
    except (socket.gaierror, socket.herror, OSError):
        return False


def check_forbidden_content(text):
    violations = []
    seen = set()
    for pattern, message in FORBIDDEN_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE) and message not in seen:
            violations.append(message)
            seen.add(message)
    return violations


_rate_limits = defaultdict(list)


def rate_limited(key, max_requests=5, window=60):
    now = time.time()
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < window]
    if len(_rate_limits[key]) >= max_requests:
        return True
    _rate_limits[key].append(now)
    return False


def audit(action, entity_type, entity_id, details="", performed_by="system",
          previous_status=None, new_status=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (action, entity_type, entity_id, details, "
        "performed_by, previous_status, new_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (action, entity_type, entity_id, details, performed_by,
         previous_status, new_status),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Permission decorators (centralized RBAC)
# ---------------------------------------------------------------------------
from functools import wraps


def require_admin_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


def require_approved_contractor(f):
    """Requires an approved contractor session. Injects `contractor` into kwargs."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "contractor_id" not in session:
            return redirect(url_for("login_contractor"))
        db = get_db()
        contractor = db.execute(
            "SELECT * FROM contractors WHERE id = ?", (session["contractor_id"],)
        ).fetchone()
        if not contractor:
            session.clear()
            return redirect(url_for("index"))
        if contractor["status"] != "approved":
            # Allow login but pass contractor so route can show appropriate message
            kwargs["contractor"] = contractor
            kwargs["approved"] = False
            return f(*args, **kwargs)
        kwargs["contractor"] = contractor
        kwargs["approved"] = True
        return f(*args, **kwargs)
    return decorated


def require_verified_local(f):
    """Requires a verified Tier 1 local session. Injects `local` into kwargs."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "local_id" not in session:
            return redirect(url_for("login_local"))
        db = get_db()
        loc = db.execute(
            "SELECT * FROM tier1_posters WHERE id = ?", (session["local_id"],)
        ).fetchone()
        if not loc or not loc["verified"]:
            session.clear()
            return redirect(url_for("index"))
        kwargs["local"] = loc
        return f(*args, **kwargs)
    return decorated


# ==========================================================================
# Routes: Public
# ==========================================================================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/feed")
def feed():
    db = get_db()

    # Read filters from query params
    state = request.args.get("state", "").strip()
    region = request.args.get("region", "").strip()
    classification = request.args.get("classification", "").strip()
    poster_type = request.args.get("poster_type", "").strip()  # tier1 / tier2

    sql = """
        SELECT * FROM posts
        WHERE status != 'removed'
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
          AND (
                (poster_type = 'tier1' AND poster_id IN
                    (SELECT id FROM tier1_posters WHERE verified = 1))
                OR
                (poster_type = 'tier2' AND poster_id IN
                    (SELECT id FROM contractors WHERE status = 'approved'))
          )
    """
    params = []

    # Region filter (simple column match)
    if region and region in REGIONS:
        sql += " AND region = ?"
        params.append(region)

    # Poster type filter (simple column match)
    if poster_type in ("tier1", "tier2"):
        sql += " AND poster_type = ?"
        params.append(poster_type)

    # State filter (JSON text stored like ["TX","LA"] -> match quoted token)
    if state and state in US_STATES:
        sql += " AND states LIKE ?"
        params.append(f'%"{state}"%')

    # Classification filter (JSON text stored like ["JL","GF"] -> match quoted token)
    valid_class_codes = {c[0] for c in CLASSIFICATIONS}
    if classification and classification in valid_class_codes:
        sql += " AND classification_needed LIKE ?"
        params.append(f'%"{classification}"%')

    sql += " ORDER BY created_at DESC"

    posts = db.execute(sql, params).fetchall()

    return render_template(
        "feed.html",
        posts=posts,
        filters={
            "state": state,
            "region": region,
            "classification": classification,
            "poster_type": poster_type,
        },
        US_STATES=US_STATES,
        REGIONS=REGIONS,
        CLASSIFICATIONS=CLASSIFICATIONS,
    )

@app.route("/feed/<int:post_id>")
def feed_details(post_id):
    db = get_db()
    post = db.execute("""
        SELECT * FROM posts
        WHERE id = ?
          AND status != 'removed'
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
          AND (
                (poster_type = 'tier1' AND poster_id IN
                    (SELECT id FROM tier1_posters WHERE verified = 1))
                OR
                (poster_type = 'tier2' AND poster_id IN
                    (SELECT id FROM contractors WHERE status = 'approved'))
          )
        LIMIT 1
    """, (post_id,)).fetchone()

    if not post:
        abort(404)

    return render_template(
        "feed_details.html",
        post=post,
        CLASSIFICATIONS=CLASSIFICATIONS,
        TIER2_DISCLAIMER=TIER2_DISCLAIMER,
    )

# ==========================================================================
# Routes: Contractor Registration & Login
# ==========================================================================

@app.route("/register/contractor", methods=["GET", "POST"])
def register_contractor():
    if request.method == "POST":
        if rate_limited(f"reg:{request.remote_addr}", max_requests=3, window=300):
            return render_template(
                "register_contractor.html",
                errors=["Too many attempts. Please try again later."],
                form=request.form, success=False,
            )

        errors = []
        f = request.form

        # --- Section 1: Company Identity ---
        company_legal_name = f.get("company_legal_name", "").strip()
        headquarters_state = f.get("headquarters_state", "").strip()
        company_website = f.get("company_website", "").strip()
        company_email = f.get("company_email", "").strip()
        primary_contact_name = f.get("primary_contact_name", "").strip()
        primary_contact_phone = f.get("primary_contact_phone", "").strip()

        # NEW: Password fields
        password = f.get("password", "")
        password_confirm = f.get("password_confirm", "")

        if not company_legal_name:
            errors.append("Company legal name is required.")
        if not headquarters_state or headquarters_state not in US_STATES:
            errors.append("Headquarters state is required.")
        if not company_website:
            errors.append("Company website is required.")
        if not company_email:
            errors.append("Company email is required.")
        if not primary_contact_name:
            errors.append("Primary contact name is required.")
        if not primary_contact_phone:
            errors.append("Primary contact phone is required.")

        # NEW: Password validation (simple + strong enough for beta)
        if not password or len(password) < 10:
            errors.append("Password must be at least 10 characters.")
        if password != password_confirm:
            errors.append("Passwords do not match.")

        #Domain validation (FLAG ONLY — do not block signup)
        email_domain_validated = False
        website_resolves = False

        email_domain = None
        website_domain = None

        if company_email:
            email_domain = get_email_domain(company_email)

        if company_website:
            website_domain = get_website_domain(company_website)

        # Don't block signup if it's a free email, mismatch, or non-resolving domain.
        # Just record flags for admin review.
        if email_domain and website_domain and domains_match(email_domain, website_domain):
            email_domain_validated = True

        if website_domain and domain_resolves(website_domain):
            website_resolves = True


        # --- Section 2: Industry Legitimacy ---
        contractor_type = f.get("contractor_type", "").strip()
        states_of_operation = f.getlist("states_of_operation")
        ibew_signatory = 1 if f.get("ibew_signatory") else 0
        clears_through_ibew = 1 if f.get("clears_through_ibew") else 0
        locals_cleared_through = f.get("locals_cleared_through", "").strip()

        if not contractor_type or contractor_type not in CONTRACTOR_TYPES:
            errors.append("Contractor type is required.")
        if not states_of_operation:
            errors.append("At least one state of operation is required.")

        # --- Section 3: Intent & Acknowledgments ---
        intent_mobilization = 1 if f.get("intent_mobilization") else 0
        intent_advisories = 1 if f.get("intent_advisories") else 0
        ack_no_dispatch = 1 if f.get("ack_no_dispatch") else 0
        ack_clear_through_local = 1 if f.get("ack_clear_through_local") else 0
        ack_no_collect_info = 1 if f.get("ack_no_collect_info") else 0

        if not intent_mobilization and not intent_advisories:
            errors.append("Select at least one intended use.")
        if not ack_no_dispatch:
            errors.append("You must acknowledge: this platform does not dispatch or hire.")
        if not ack_clear_through_local:
            errors.append("You must acknowledge: all work clears through IBEW locals.")
        if not ack_no_collect_info:
            errors.append("You must acknowledge: no collecting worker info.")

        # Duplicate check
        if company_email and not errors:
            db = get_db()
            existing = db.execute(
                "SELECT id FROM contractors WHERE company_email = ?",
                (company_email,),
            ).fetchone()
            if existing:
                errors.append("An account with this email already exists.")

        if errors:
            return render_template(
                "register_contractor.html",
                errors=errors, form=request.form, success=False,
            )

        # NEW: hash the password
        password_hash = generate_password_hash(password)

        db = get_db()
        db.execute("""
            INSERT INTO contractors (
                company_legal_name, headquarters_state, company_website,
                company_email, password_hash, primary_contact_name, primary_contact_phone,
                contractor_type, states_of_operation,
                ibew_signatory, clears_through_ibew, locals_cleared_through,
                intent_mobilization, intent_advisories,
                ack_no_dispatch, ack_clear_through_local, ack_no_collect_info,
                email_domain_validated, website_resolves
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            company_legal_name, headquarters_state, company_website,
            company_email, password_hash, primary_contact_name, primary_contact_phone,
            contractor_type, json.dumps(states_of_operation),
            ibew_signatory, clears_through_ibew, locals_cleared_through,
            intent_mobilization, intent_advisories,
            ack_no_dispatch, ack_clear_through_local, ack_no_collect_info,
            1 if email_domain_validated else 0,
            1 if website_resolves else 0,
        ))
        db.commit()

        new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        audit("register", "contractor", new_id, company_legal_name, "self")
        return render_template(
            "register_contractor.html",
            errors=[], form=MultiDict(), success=True,
        )

    return render_template(
        "register_contractor.html",
        errors=[], form=MultiDict(), success=False,
    )


@app.route("/login/contractor", methods=["GET", "POST"])
def login_contractor():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            error = "Please enter your email and password."
        else:
            db = get_db()
            c = db.execute(
                "SELECT * FROM contractors WHERE company_email = ?", (email,)
            ).fetchone()

            # Generic error message (don’t leak which part is wrong)
            if not c or (not c["password_hash"]) or (not check_password_hash(c["password_hash"], password)):

                error = "Invalid email or password."
            else:
                # Allow login for any status; dashboard/posting controls enforce restrictions
                session.clear()
                session["contractor_id"] = c["id"]
                session["contractor_email"] = c["company_email"]
                session["contractor_name"] = c["company_legal_name"]
                return redirect(url_for("dashboard_contractor"))

    return render_template("login.html", role="contractor", error=error)


@app.route("/login/local", methods=["GET", "POST"])
def login_local():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email:
            error = "Please enter your email."
        else:
            db = get_db()
            loc = db.execute(
                "SELECT * FROM tier1_posters WHERE contact_email = ?", (email,)
            ).fetchone()
            if not loc:
                error = "No local account found with that email."
            elif not loc["verified"]:
                error = "Your account is not yet verified by admin."
            else:
                session.clear()
                session["local_id"] = loc["id"]
                session["local_email"] = loc["contact_email"]
                session["local_name"] = f"IBEW Local {loc['local_number']}"
                return redirect(url_for("dashboard_local"))
    return render_template("login.html", role="local", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ==========================================================================
# Routes: Dashboards
# ==========================================================================

@app.route("/dashboard/contractor")
def dashboard_contractor():
    if "contractor_id" not in session:
        return redirect(url_for("login_contractor"))

    db = get_db()
    contractor = db.execute(
        "SELECT * FROM contractors WHERE id = ?",
        (session["contractor_id"],),
    ).fetchone()

    if not contractor:
        session.clear()
        return redirect(url_for("login_contractor"))

    approved = contractor["status"] == "approved"

    posts = []
    if approved:
        posts = db.execute(
            "SELECT * FROM posts WHERE poster_type = 'tier2' AND poster_id = ? "
            "ORDER BY created_at DESC",
            (contractor["id"],),
        ).fetchall()

    return render_template(
        "dashboard_contractor.html",
        contractor=contractor,
        approved=approved,
        posts=posts,
    )

@app.route("/dashboard/local")
@require_verified_local
def dashboard_local(local):
    db = get_db()
    posts = db.execute(
        "SELECT * FROM posts WHERE poster_type = 'tier1' AND poster_id = ? "
        "ORDER BY created_at DESC", (local["id"],)
    ).fetchall()
    return render_template("dashboard_local.html", local=local, posts=posts)


# ==========================================================================
# Routes: Post Creation
# ==========================================================================

@app.route("/post/create", methods=["GET", "POST"])
def create_post():
    poster_type = None
    poster = None
    db = get_db()

    if "contractor_id" in session:
        poster_type = "tier2"
        poster = db.execute(
            "SELECT * FROM contractors WHERE id = ? AND status = 'approved'",
            (session["contractor_id"],),
        ).fetchone()
    elif "local_id" in session:
        poster_type = "tier1"
        poster = db.execute(
            "SELECT * FROM tier1_posters WHERE id = ? AND verified = 1",
            (session["local_id"],),
        ).fetchone()

    if not poster:
        return redirect(url_for("index"))

    allowed_types = POST_TYPES_TIER1 if poster_type == "tier1" else POST_TYPES_TIER2

    if request.method == "POST":
        if rate_limited(f"post:{request.remote_addr}", max_requests=10, window=300):
            return render_template(
                "create_post.html", poster_type=poster_type, poster=poster,
                allowed_types=allowed_types,
                errors=["Too many attempts. Please slow down."],
                form=request.form,
            )

        errors = []
        f = request.form

        post_type = f.get("post_type", "").strip()
        region = f.get("region", "").strip()
        states = f.getlist("states")
        expected_start_window = f.get("expected_start_window", "").strip()
        classifications = f.getlist("classification")
        clearing_locals = f.get("clearing_locals", "").strip()
        hall_contact = f.get("hall_contact", "").strip()
        short_notes = f.get("short_notes", "").strip()

        if not post_type or post_type not in allowed_types:
            errors.append("Valid post type is required.")
        if not region or region not in REGIONS:
            errors.append("Region is required.")
        if not states:
            errors.append("At least one state is required.")
        if not expected_start_window:
            errors.append("Expected start window is required.")
        if not classifications:
            errors.append("At least one classification is required.")
        if not clearing_locals:
            errors.append("Clearing local(s) is required.")
        if short_notes and len(short_notes) > 500:
            errors.append("Notes must be 500 characters or fewer.")

        # Tier 2: forbidden content check
        if poster_type == "tier2" and short_notes:
            violations = check_forbidden_content(short_notes)
            for v in violations:
                errors.append(f"Forbidden content: {v}")

        if errors:
            return render_template(
                "create_post.html", poster_type=poster_type, poster=poster,
                allowed_types=allowed_types, errors=errors, form=request.form,
            )

        if poster_type == "tier1":
            display_name = f"IBEW Local {poster['local_number']}"
        else:
            display_name = poster["company_legal_name"]


        expires_at = datetime.utcnow() + timedelta(days=30)

        db.execute("""
            INSERT INTO posts (
                poster_type, poster_id, poster_display_name, post_type,
                region, states, expected_start_window,
                classification_needed, clearing_locals,
                hall_contact, short_notes, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            poster_type, poster["id"], display_name, post_type,
            region, json.dumps(states), expected_start_window,
            json.dumps(classifications), clearing_locals,
            hall_contact, short_notes, expires_at
        ))
        db.commit()
        new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        audit("create_post", "post", new_id, f"{post_type} by {display_name}",
              session.get("contractor_email") or session.get("local_email", "unknown"))

        if poster_type == "tier2":
            return redirect(url_for("dashboard_contractor"))
        return redirect(url_for("dashboard_local"))

    return render_template(
        "create_post.html", poster_type=poster_type, poster=poster,
        allowed_types=allowed_types, errors=[], form=MultiDict(),
    )


# ==========================================================================
# Routes: Admin
# ==========================================================================

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if session.get("is_admin"):
        return redirect(url_for("admin_contractors"))
    error = None
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["is_admin"] = True
            return redirect(url_for("admin_contractors"))
        error = "Invalid password."
    return render_template("admin_login.html", error=error)


@app.route("/admin/contractors")
@require_admin_session
def admin_contractors():
    db = get_db()
    pending = db.execute(
        "SELECT * FROM contractors WHERE status='pending' ORDER BY created_at"
    ).fetchall()
    approved = db.execute(
        "SELECT * FROM contractors WHERE status='approved' ORDER BY updated_at DESC"
    ).fetchall()
    denied = db.execute(
        "SELECT * FROM contractors WHERE status='denied' ORDER BY updated_at DESC"
    ).fetchall()
    revoked = db.execute(
        "SELECT * FROM contractors WHERE status='revoked' ORDER BY revoked_at DESC"
    ).fetchall()
    return render_template(
        "admin_contractors.html",
        pending=pending, approved=approved, denied=denied, revoked=revoked,
    )


@app.route("/admin/contractors/<int:cid>/approve", methods=["POST"])
@require_admin_session
def admin_approve_contractor(cid):
    notes = request.form.get("notes", "").strip()
    db = get_db()
    c = db.execute("SELECT status FROM contractors WHERE id = ?", (cid,)).fetchone()
    prev_status = c["status"] if c else None
    # Allow: pending → approved, revoked → approved (reactivation)
    if prev_status not in ("pending", "revoked"):
        return redirect(url_for("admin_contractors"))
    db.execute(
        "UPDATE contractors SET status='approved', admin_notes=?, "
        "revoked_at=NULL, revoked_by=NULL, revoked_reason=NULL, "
        "updated_at=CURRENT_TIMESTAMP WHERE id=?", (notes, cid),
    )
    db.commit()
    action = "reactivate" if prev_status == "revoked" else "approve"
    audit(action, "contractor", cid, notes, "admin",
          previous_status=prev_status, new_status="approved")
    return redirect(url_for("admin_contractors"))


@app.route("/admin/contractors/<int:cid>/deny", methods=["POST"])
@require_admin_session
def admin_deny_contractor(cid):
    notes = request.form.get("notes", "").strip()
    db = get_db()
    c = db.execute("SELECT status FROM contractors WHERE id = ?", (cid,)).fetchone()
    prev_status = c["status"] if c else None
    if prev_status != "pending":
        return redirect(url_for("admin_contractors"))
    db.execute(
        "UPDATE contractors SET status='denied', admin_notes=?, "
        "updated_at=CURRENT_TIMESTAMP WHERE id=?", (notes, cid),
    )
    db.commit()
    audit("deny", "contractor", cid, notes, "admin",
          previous_status=prev_status, new_status="denied")
    return redirect(url_for("admin_contractors"))


@app.route("/admin/contractors/<int:cid>/revoke", methods=["POST"])
@require_admin_session
def admin_revoke_contractor(cid):
    reason = request.form.get("reason", "").strip()
    db = get_db()
    c = db.execute("SELECT status FROM contractors WHERE id = ?", (cid,)).fetchone()
    if not c or c["status"] != "approved":
        return redirect(url_for("admin_contractors"))
    db.execute(
        "UPDATE contractors SET status='revoked', "
        "revoked_at=CURRENT_TIMESTAMP, revoked_by='admin', revoked_reason=?, "
        "updated_at=CURRENT_TIMESTAMP WHERE id=?", (reason, cid),
    )
    db.commit()
    audit("revoke", "contractor", cid, reason or "No reason given", "admin",
          previous_status="approved", new_status="revoked")
    return redirect(url_for("admin_contractors"))


@app.route("/admin/locals")
@require_admin_session
def admin_locals():
    db = get_db()
    locals_list = db.execute(
        "SELECT * FROM tier1_posters ORDER BY created_at"
    ).fetchall()
    return render_template(
        "admin_locals.html", locals_list=locals_list,
        errors=[], form=MultiDict(),
    )


@app.route("/admin/locals/create", methods=["POST"])
@require_admin_session
def admin_create_local():
    errors = []
    f = request.form
    local_number = f.get("local_number", "").strip()
    local_name = f.get("local_name", "").strip()
    city = f.get("city", "").strip()
    state = f.get("state", "").strip()
    contact_email = f.get("contact_email", "").strip()
    contact_phone = f.get("contact_phone", "").strip()

    if not local_number:
        errors.append("Local number is required.")
    if not contact_email:
        errors.append("Contact email is required.")

    if not errors:
        db = get_db()
        existing = db.execute(
            "SELECT id FROM tier1_posters WHERE contact_email = ?", (contact_email,)
        ).fetchone()
        if existing:
            errors.append("A local with this email already exists.")

    if errors:
        db = get_db()
        locals_list = db.execute(
            "SELECT * FROM tier1_posters ORDER BY created_at"
        ).fetchall()
        return render_template(
            "admin_locals.html", locals_list=locals_list,
            errors=errors, form=request.form,
        )

    db = get_db()
    db.execute("""
        INSERT INTO tier1_posters (local_number, local_name, city, state,
            contact_email, contact_phone, verified)
        VALUES (?, ?, ?, ?, ?, ?, 1)
    """, (local_number, local_name, city, state, contact_email, contact_phone))
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    audit("create", "tier1_poster", new_id, f"Local {local_number}", "admin")
    return redirect(url_for("admin_locals"))


@app.route("/admin/locals/<int:lid>/toggle", methods=["POST"])
@require_admin_session
def admin_toggle_local(lid):
    db = get_db()
    loc = db.execute("SELECT * FROM tier1_posters WHERE id = ?", (lid,)).fetchone()
    if loc:
        new_val = 0 if loc["verified"] else 1
        db.execute(
            "UPDATE tier1_posters SET verified = ? WHERE id = ?", (new_val, lid)
        )
        db.commit()
        audit("toggle_verified", "tier1_poster", lid,
              f"verified={new_val}", "admin")
    return redirect(url_for("admin_locals"))


@app.route("/admin/posts")
@require_admin_session
def admin_posts():
    db = get_db()
    posts = db.execute(
        "SELECT * FROM posts ORDER BY created_at DESC"
    ).fetchall()
    return render_template("admin_posts.html", posts=posts)


@app.route("/admin/posts/<int:pid>/status", methods=["POST"])
@require_admin_session
def admin_post_status(pid):
    new_status = request.form.get("status", "")
    if new_status in ("active", "filled", "canceled", "expired", "removed"):
        db = get_db()
        p = db.execute("SELECT status FROM posts WHERE id = ?", (pid,)).fetchone()
        prev = p["status"] if p else None
        db.execute(
            "UPDATE posts SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (new_status, pid),
        )
        db.commit()
        audit("change_status", "post", pid, f"status={new_status}", "admin",
              previous_status=prev, new_status=new_status)
    return redirect(url_for("admin_posts"))


@app.route("/admin/audit")
@require_admin_session
def admin_audit():
    db = get_db()
    entries = db.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    return render_template("admin_audit.html", entries=entries)


# ==========================================================================
# Main
# ==========================================================================

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)

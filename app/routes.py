from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Queue, Token, QueueSettings, Counter
from . import db
from datetime import datetime, timedelta

def select_best_counter(queue_id):
    counters = Counter.query.filter_by(
        queue_id=queue_id,
        is_active=True
    ).all()

    selected = None
    min_wait = None

    for c in counters:
        active = Token.query.filter_by(
            counter_id=c.id,
            status="ACTIVE"
        ).count()

        wait_time = active * c.avg_service_time

        if min_wait is None or wait_time < min_wait:
            min_wait = wait_time
            selected = c

    return selected, min_wait

def calculate_wait_time(queue_id, token_number):
    settings = QueueSettings.query.filter_by(queue_id=queue_id).first()
    if not settings:
        return None

    people_ahead = Token.query.filter(
        Token.queue_id == queue_id,
        Token.status == "ACTIVE",
        Token.token_number < token_number
    ).count()

    wait_time = (people_ahead * settings.avg_service_time) / settings.counters
    return round(wait_time)


main = Blueprint("main", __name__)
from datetime import datetime

def expire_tokens():
    now = datetime.utcnow()

    expired_tokens = Token.query.filter(
        Token.status == "ACTIVE",
        Token.expires_at < now
    ).all()

    for token in expired_tokens:
        token.status = "EXPIRED"

    if expired_tokens:
        db.session.commit()

def activate_scheduled_tokens():
    now = datetime.utcnow()

    scheduled_tokens = Token.query.filter(
        Token.status == "SCHEDULED",
        Token.scheduled_time <= now
    ).all()

    for token in scheduled_tokens:
        token.status = "ACTIVE"

    if scheduled_tokens:
        db.session.commit()


@main.before_app_request
def auto_update_tokens():
    expire_tokens()
    activate_scheduled_tokens()

# ---------------- INDEX ---------------- #
@main.route("/")
def index():
    return render_template("landing.html")

# ---------------- REGISTER ---------------- #
@main.route("/register", methods=["POST"])
def register():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    if not name or not email or not password or not confirm:
        return render_template("login_register.html", error="All fields required", show_register=True)

    if password != confirm:
        return render_template("login_register.html", error="Passwords do not match", show_register=True)

    if User.query.filter_by(email=email).first():
        return render_template("login_register.html", error="Email already exists", show_register=True)

    hashed = generate_password_hash(password)
    user = User(name=name, email=email, password=hashed)

    db.session.add(user)
    db.session.commit()

    return render_template("login_register.html", success="Account created! Login now.")

# ---------------- LOGIN ---------------- #
@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # 🔥 clear old session
        session.clear()

        email = request.form.get("email", "").lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            return render_template("login_register.html", error="Invalid credentials")

        # ✅ fresh session for every login
        session["user_id"] = user.id
        session["role"] = user.role

        return redirect(
            url_for("main.admin_dashboard") if user.role == "admin" else url_for("main.user_dashboard")
        )

    # GET request → show login page (or register if query param exists)
    show_register = request.args.get("show_register", "false").lower() == "true"
    return render_template("login_register.html", show_register=show_register)


# ---------------- USER DASHBOARD ---------------- #
@main.route("/user_dashboard")
def user_dashboard():
    if session.get("role") != "user":
        return redirect(url_for("main.index"))

    return render_template("user_dashboard.html", guest=False)


# ---------------- ADMIN DASHBOARD ---------------- #
@main.route("/admin_dashboard")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect(url_for("main.index"))
    return render_template("admin_dashboard.html")
def admin_tokens():
    if session.get("role") != "admin":
        return jsonify([])

    tokens = (
        db.session.query(Token, Queue, User)
        .join(Queue, Token.queue_id == Queue.id)
        .join(User, Token.user_id == User.id)
        .filter(Token.status == "ACTIVE")
        .order_by(Token.created_at)
        .all()
    )

# ---------------- LOGOUT ---------------- #
@main.route("/logout")
def logout():
    session.clear()
    session.modified = True   # 🔥 force browser cookie update
    return redirect(url_for("main.index"))


# ---------------- GUEST ---------------- #
@main.route("/guest_dashboard")
def guest_dashboard():
    return render_template("user_dashboard.html", guest=True)

# ---------------- TOKEN REQUEST ---------------- #

@main.route("/request_token", methods=["POST"])
def request_token():
    data = request.get_json()
    queue_name = data.get("queue")
    scheduled_time = data.get("scheduled_time")  # ✅ NEW

    if not session.get("user_id"):
        return jsonify({"error": "Login required"}), 401

    expire_tokens()

    data = request.get_json()
    queue_name = data.get("queue")

    queue = Queue.query.filter_by(name=queue_name).first()
    if not queue:
        return jsonify({"error": "Queue not found"}), 404

    # 🔒 ONE ACTIVE TOKEN RULE
    active_token = Token.query.filter_by(
        user_id=session["user_id"],
        status="ACTIVE"
    ).first()

    if active_token:
        return jsonify({"error": "You already have an active token"}), 400

    # 🔢 next token number
    last_token = (
        Token.query
        .filter(Token.queue_id == queue.id)
        .order_by(Token.token_number.desc())
        .first()
    )
    token_number = 1 if not last_token else last_token.token_number + 1

    # 🎯 SELECT BEST COUNTER
    counters = Counter.query.filter_by(
        queue_id=queue.id,
        is_active=True
    ).all()

    if not counters:
        return jsonify({"error": "No counters available"}), 400

    selected_counter = None
    min_wait = None

    for c in counters:
        active_count = Token.query.filter_by(
            counter_id=c.id,
            status="ACTIVE"
        ).count()

        wait_time = active_count * c.avg_service_time

        if min_wait is None or wait_time < min_wait:
            min_wait = wait_time
            selected_counter = c

    # 🎫 CREATE TOKEN
    token = Token(
    user_id=session["user_id"],
    queue_id=queue.id,
    counter_id=selected_counter.id,
    token_number=token_number,
    status="SCHEDULED" if scheduled_time else "ACTIVE",
    scheduled_time=(
        datetime.fromisoformat(scheduled_time)
        - timedelta(hours=5, minutes=30)
    ) if scheduled_time else None,
    created_at=datetime.utcnow(),
    expires_at=datetime.utcnow() + timedelta(minutes=30)
)

    db.session.add(token)
    db.session.commit()

    return jsonify({
        "token": token_number,
        "counter": selected_counter.counter_number,
        "estimated_wait": min_wait
    })

@main.route("/admin/queue_status")
def admin_queue_status():
    if not session.get("user_id"):
        return jsonify([])

    admin_id = session["user_id"]

    # ONLY queues managed by this admin
    queues = Queue.query.filter_by(admin_id=admin_id).all()

    result = []

    for q in queues:
        waiting = Token.query.filter_by(
            queue_id=q.id,
            status="ACTIVE"
        ).count()

        result.append({
            "id": q.id,
            "name": q.name,
            "waiting": waiting,
            "status": q.status
        })

    return jsonify(result)

@main.route("/admin/next_token", methods=["POST"])
def next_token():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    queue_id = data.get("queue_id")

    token = (
        Token.query
        .filter(
            Token.queue_id == queue_id,
            Token.status == "ACTIVE"
        )
        .order_by(Token.created_at.asc())
        .first()
    )

    if not token:
        return jsonify({"message": "No active tokens"}), 200

    token.status = "SERVED"
    token.served_at = datetime.utcnow()   # 🔥 THIS WAS MISSING
    db.session.commit()


    return jsonify({
        "message": "Token served",
        "token_number": token.token_number
    })

@main.route("/admin/test_next")
def test_next():
    if session.get("role") != "admin":
        return "Not admin", 403

    token = Token.query.filter_by(
        queue_id=1,
        status="ACTIVE"
    ).order_by(Token.created_at.asc()).first()

    if not token:
        return "No active tokens"

    token.status = "SERVED"
    db.session.commit()

    return f"Token {token.token_number} served"


#@main.route("/debug")
#def debug():
    return {
        "user_id": session.get("user_id"),
        "role": session.get("role")
    }

@main.route("/user/token_status")
def user_token_status():
    if not session.get("user_id"):
        return jsonify({"has_token": False})

    token = Token.query.filter(
        Token.user_id == session["user_id"],
        Token.status.in_(["ACTIVE", "SCHEDULED", "PAUSED"])
    ).order_by(Token.created_at.desc()).first()

    # 🚫 NO TOKEN
    if not token:
        return jsonify({"has_token": False})

    now = datetime.utcnow()

    # ⏰ AUTO-RESUME PAUSED TOKEN
    if token.status == "PAUSED":
        if token.postponed_until and now >= token.postponed_until:
            token.status = "ACTIVE"
            token.postponed_until = None
            db.session.commit()
        else:
            return jsonify({
                "has_token": True,
                "status": "PAUSED",
                "token_number": token.token_number
            })

    # 🕒 SCHEDULED TOKEN
    if token.status == "SCHEDULED":
        display_time = token.scheduled_time + timedelta(hours=5, minutes=30)

        return jsonify({
            "has_token": True,
            "status": "SCHEDULED",
            "token_number": token.token_number,
            "scheduled_time": display_time.strftime("%I:%M %p")
        })

    # ✅ ACTIVE TOKEN
    counter = Counter.query.get(token.counter_id)

    people_ahead = Token.query.filter(
        Token.counter_id == token.counter_id,
        Token.status == "ACTIVE",
        Token.created_at < token.created_at
    ).count()

    if people_ahead == 0:
        return jsonify({
            "has_token": True,
            "status": "YOUR_TURN",
            "token_number": token.token_number,
            "counter": counter.counter_number
        })

    wait_time = people_ahead * counter.avg_service_time

    return jsonify({
        "has_token": True,
        "status": "WAITING",
        "token_number": token.token_number,
        "estimated_wait": wait_time
    })

@main.route("/admin/set_queue_settings", methods=["POST"])
def set_queue_settings():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()

    queue_id = data.get("queue_id")
    counters = data.get("counters")
    service_times = data.get("service_times")

    if not queue_id or not counters or not service_times:
        return jsonify({"error": "Invalid input"}), 400

    active_tokens = Token.query.filter_by(
        queue_id=queue_id,
        status="ACTIVE"
    ).count()

    # 🚫 Block optimization if tokens exist
    if active_tokens > 0:
        return jsonify({
            "error": "Cannot change optimization while tokens are active"
        }), 400

    # 🧹 Remove old counters
    Counter.query.filter_by(queue_id=queue_id).delete()

    # ➕ Insert new counters
    for i, time in enumerate(service_times, start=1):
        counter = Counter(
            queue_id=queue_id,
            counter_number=i,
            avg_service_time=time,
            is_active=True
        )
        db.session.add(counter)

    # ⚙️ Update queue settings
    settings = QueueSettings.query.filter_by(queue_id=queue_id).first()
    if not settings:
        settings = QueueSettings(queue_id=queue_id, counters=counters)
        db.session.add(settings)
    else:
        settings.counters = counters

    db.session.commit()

    return jsonify({"message": "Queue optimization saved successfully"})


@main.route("/user/account")
def user_account():
    # 🚫 block admin completely
    if session.get("role") != "user":
        return jsonify({"error": "Unauthorized"}), 403

    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.get(user_id)

    tokens = Token.query.filter_by(user_id=user.id).all()

    history = [{
        "queue": Queue.query.get(t.queue_id).name,
        "token": t.token_number,
        "status": t.status
    } for t in tokens]

    return jsonify({
        "name": user.name,
        "email": user.email,
        "total_tokens": len(tokens),
        "history": history
    })


@main.route("/user/change_password", methods=["POST"])
def change_password():
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    current = data.get("current")
    new = data.get("new")

    user = User.query.get(session["user_id"])

    if not check_password_hash(user.password, current):
        return jsonify({"error": "Current password incorrect"}), 400

    user.password = generate_password_hash(new)
    db.session.commit()

    return jsonify({"message": "Password updated successfully"})

@main.route("/admin/my_queues")
def admin_my_queues():
    if session.get("role") != "admin":
        return jsonify([])

    admin_id = session.get("user_id")

    queues = Queue.query.filter_by(admin_id=admin_id).all()

    return jsonify([
        {"id": q.id, "name": q.name}
        for q in queues
    ])

@main.route("/admin/my_services")
def admin_services():
    if not session.get("user_id"):
        return jsonify([])

    admin_id = session["user_id"]

    services = Queue.query.filter_by(admin_id=admin_id).all()

    return jsonify([
        {"id": q.id, "name": q.name}
        for q in services
    ])

# ---------------- ABOUT PAGE ---------------- #
@main.route("/about")
def about():
    return render_template("about.html")

# ---------------- CONTACT PAGE ---------------- #
@main.route("/contact")
def contact():
    return render_template("contact.html")

@main.route("/user/cancel_token", methods=["POST"])
def cancel_token():
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401

    token = Token.query.filter(
        Token.user_id == session["user_id"],
        Token.status.in_(["ACTIVE", "PAUSED", "SCHEDULED"])
    ).first()

    if not token:
        return jsonify({"error": "No active token"}), 400

    token.status = "CANCELLED"
    db.session.commit()

    return jsonify({
        "message": "Token cancelled",
        "reset": True
    })

@main.route("/user/pause_token", methods=["POST"])
def pause_token():
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401

    token = Token.query.filter_by(
        user_id=session["user_id"],
        status="ACTIVE"
    ).first()

    if not token:
        return jsonify({"error": "No active token"}), 400

    token.status = "PAUSED"
    token.postponed_until = datetime.utcnow() + timedelta(minutes=7)
    db.session.commit()

    return jsonify({"message": "Your turn is postponed by 7 minutes"})

@main.route("/admin/queue_tokens/<int:queue_id>")
def admin_queue_tokens(queue_id):
    if session.get("role") != "admin":
        return jsonify([]), 403

    tokens = (
        db.session.query(Token, User)
        .join(User, Token.user_id == User.id)
        .filter(Token.queue_id == queue_id)
        .order_by(Token.created_at.asc())
        .all()
    )

    result = []

    for token, user in tokens:
        result.append({
            "token_id": token.id,
            "token_number": token.token_number,
            "user_name": user.name,
            "email": user.email,
            "status": token.status,
            "joined_at": token.created_at.strftime("%Y-%m-%d %H:%M"),
            "scheduled_time": token.scheduled_time.strftime("%H:%M") if token.scheduled_time else None,
            "postponed_until": token.postponed_until.strftime("%H:%M") if token.postponed_until else None
        })

    return jsonify(result)

@main.route("/admin/remove_token", methods=["POST"])
def admin_remove_token():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    token_id = data.get("token_id")

    token = Token.query.get(token_id)
    if not token:
        return jsonify({"error": "Token not found"}), 404

    token.status = "CANCELLED"
    db.session.commit()

    return jsonify({"message": "Token removed by admin"})

@main.route("/admin/resume_token", methods=["POST"])
def admin_resume_token():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    token_id = data.get("token_id")

    token = Token.query.get(token_id)
    if not token or token.status != "PAUSED":
        return jsonify({"error": "Invalid token"}), 400

    token.status = "ACTIVE"
    token.postponed_until = None
    db.session.commit()

    return jsonify({"message": "Token resumed"})

@main.route("/public/now_serving")
def now_serving():
    active = (
        db.session.query(Token, Queue)
        .join(Queue, Token.queue_id == Queue.id)
        .filter(Token.status == "ACTIVE")
        .order_by(Token.created_at.asc())
        .first()
    )

    if not active:
        return jsonify({"now_serving": None})

    token, queue = active

    return jsonify({
        "queue": queue.name,
        "token_number": token.token_number
    })

from sqlalchemy import func
from datetime import datetime

@main.route("/admin/reports")
def admin_reports():
    # Fetch all tokens
    tokens = Token.query.all()

    if not tokens:
        return jsonify({
            "total_tokens": 0,
            "avg_wait": 0,
            "hourly": [],
            "efficiency": 0
        })

    # Total tokens served
    total_tokens = len(tokens)

    # Average wait time (created → served)
    served_tokens = [t for t in tokens if t.status == "SERVED"]

    if served_tokens:
        avg_wait = sum(
            [(t.served_at - t.created_at).seconds / 60
             for t in served_tokens if t.served_at]
        ) / len(served_tokens)
    else:
        avg_wait = 0

    # Hour-wise load
    hourly = (
        db.session.query(
            func.strftime('%H', Token.created_at),
            func.count(Token.id)
        )
        .group_by(func.strftime('%H', Token.created_at))
        .all()
    )

    hourly_data = [
        {"hour": h, "count": c} for h, c in hourly
    ]

    # Efficiency (served / total)
    efficiency = round(
        (len(served_tokens) / total_tokens) * 100, 2
    ) if total_tokens else 0

    return jsonify({
        "total_tokens": total_tokens,
        "avg_wait": round(avg_wait, 2),
        "hourly": hourly_data,
        "efficiency": efficiency
    })

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Queue, Token, QueueSettings, Counter
from . import db
from datetime import datetime, timedelta

def select_best_counter(queue_id):
    counters = Counter.query.filter_by(
        queue_id=queue_id,
        is_active=True
    ).all()

    selected = None
    min_wait = None

    for c in counters:
        active = Token.query.filter_by(
            counter_id=c.id,
            status="ACTIVE"
        ).count()

        wait_time = active * c.avg_service_time

        if min_wait is None or wait_time < min_wait:
            min_wait = wait_time
            selected = c

    return selected, min_wait

def calculate_wait_time(queue_id, token_number):
    settings = QueueSettings.query.filter_by(queue_id=queue_id).first()
    if not settings:
        return None

    people_ahead = Token.query.filter(
        Token.queue_id == queue_id,
        Token.status == "ACTIVE",
        Token.token_number < token_number
    ).count()

    wait_time = (people_ahead * settings.avg_service_time) / settings.counters
    return round(wait_time)


main = Blueprint("main", __name__)
from datetime import datetime

def expire_tokens():
    now = datetime.utcnow()

    expired_tokens = Token.query.filter(
        Token.status == "ACTIVE",
        Token.expires_at < now
    ).all()

    for token in expired_tokens:
        token.status = "EXPIRED"

    if expired_tokens:
        db.session.commit()

def activate_scheduled_tokens():
    now = datetime.utcnow()

    scheduled_tokens = Token.query.filter(
        Token.status == "SCHEDULED",
        Token.scheduled_time <= now
    ).all()

    for token in scheduled_tokens:
        token.status = "ACTIVE"

    if scheduled_tokens:
        db.session.commit()


@main.before_app_request
def auto_update_tokens():
    expire_tokens()
    activate_scheduled_tokens()

# ---------------- INDEX ---------------- #
@main.route("/")
def index():
    return render_template("landing.html")

# ---------------- REGISTER ---------------- #
@main.route("/register", methods=["POST"])
def register():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    if not name or not email or not password or not confirm:
        return render_template("login_register.html", error="All fields required", show_register=True)

    if password != confirm:
        return render_template("login_register.html", error="Passwords do not match", show_register=True)

    if User.query.filter_by(email=email).first():
        return render_template("login_register.html", error="Email already exists", show_register=True)

    hashed = generate_password_hash(password)
    user = User(name=name, email=email, password=hashed)

    db.session.add(user)
    db.session.commit()

    return render_template("login_register.html", success="Account created! Login now.")

# ---------------- LOGIN ---------------- #
@main.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # 🔥 clear old session
        session.clear()

        email = request.form.get("email", "").lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            return render_template("login_register.html", error="Invalid credentials")

        # ✅ fresh session for every login
        session["user_id"] = user.id
        session["role"] = user.role

        return redirect(
            url_for("main.admin_dashboard") if user.role == "admin" else url_for("main.user_dashboard")
        )

    # GET request → show login page (or register if query param exists)
    show_register = request.args.get("show_register", "false").lower() == "true"
    return render_template("login_register.html", show_register=show_register)


# ---------------- USER DASHBOARD ---------------- #
@main.route("/user_dashboard")
def user_dashboard():
    if session.get("role") != "user":
        return redirect(url_for("main.index"))

    return render_template("user_dashboard.html", guest=False)


# ---------------- ADMIN DASHBOARD ---------------- #
@main.route("/admin_dashboard")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect(url_for("main.index"))
    return render_template("admin_dashboard.html")
def admin_tokens():
    if session.get("role") != "admin":
        return jsonify([])

    tokens = (
        db.session.query(Token, Queue, User)
        .join(Queue, Token.queue_id == Queue.id)
        .join(User, Token.user_id == User.id)
        .filter(Token.status == "ACTIVE")
        .order_by(Token.created_at)
        .all()
    )

# ---------------- LOGOUT ---------------- #
@main.route("/logout")
def logout():
    session.clear()
    session.modified = True   # 🔥 force browser cookie update
    return redirect(url_for("main.index"))


# ---------------- GUEST ---------------- #
@main.route("/guest_dashboard")
def guest_dashboard():
    return render_template("user_dashboard.html", guest=True)

# ---------------- TOKEN REQUEST ---------------- #

@main.route("/request_token", methods=["POST"])
def request_token():
    data = request.get_json()
    queue_name = data.get("queue")
    scheduled_time = data.get("scheduled_time")  # ✅ NEW

    if not session.get("user_id"):
        return jsonify({"error": "Login required"}), 401

    expire_tokens()

    data = request.get_json()
    queue_name = data.get("queue")

    queue = Queue.query.filter_by(name=queue_name).first()
    if not queue:
        return jsonify({"error": "Queue not found"}), 404

    # 🔒 ONE ACTIVE TOKEN RULE
    active_token = Token.query.filter_by(
        user_id=session["user_id"],
        status="ACTIVE"
    ).first()

    if active_token:
        return jsonify({"error": "You already have an active token"}), 400

    # 🔢 next token number
    last_token = (
        Token.query
        .filter(Token.queue_id == queue.id)
        .order_by(Token.token_number.desc())
        .first()
    )
    token_number = 1 if not last_token else last_token.token_number + 1

    # 🎯 SELECT BEST COUNTER
    counters = Counter.query.filter_by(
        queue_id=queue.id,
        is_active=True
    ).all()

    if not counters:
        return jsonify({"error": "No counters available"}), 400

    selected_counter = None
    min_wait = None

    for c in counters:
        active_count = Token.query.filter_by(
            counter_id=c.id,
            status="ACTIVE"
        ).count()

        wait_time = active_count * c.avg_service_time

        if min_wait is None or wait_time < min_wait:
            min_wait = wait_time
            selected_counter = c

    # 🎫 CREATE TOKEN
    token = Token(
    user_id=session["user_id"],
    queue_id=queue.id,
    counter_id=selected_counter.id,
    token_number=token_number,
    status="SCHEDULED" if scheduled_time else "ACTIVE",
    scheduled_time=(
        datetime.fromisoformat(scheduled_time)
        - timedelta(hours=5, minutes=30)
    ) if scheduled_time else None,
    created_at=datetime.utcnow(),
    expires_at=datetime.utcnow() + timedelta(minutes=30)
)

    db.session.add(token)
    db.session.commit()

    return jsonify({
        "token": token_number,
        "counter": selected_counter.counter_number,
        "estimated_wait": min_wait
    })

@main.route("/admin/queue_status")
def admin_queue_status():
    if not session.get("user_id"):
        return jsonify([])

    admin_id = session["user_id"]

    # ONLY queues managed by this admin
    queues = Queue.query.filter_by(admin_id=admin_id).all()

    result = []

    for q in queues:
        waiting = Token.query.filter_by(
            queue_id=q.id,
            status="ACTIVE"
        ).count()

        result.append({
            "id": q.id,
            "name": q.name,
            "waiting": waiting,
            "status": q.status
        })

    return jsonify(result)

@main.route("/admin/next_token", methods=["POST"])
def next_token():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    queue_id = data.get("queue_id")

    token = (
        Token.query
        .filter(
            Token.queue_id == queue_id,
            Token.status == "ACTIVE"
        )
        .order_by(Token.created_at.asc())
        .first()
    )

    if not token:
        return jsonify({"message": "No active tokens"}), 200

    token.status = "SERVED"
    token.served_at = datetime.utcnow()   # 🔥 THIS WAS MISSING
    db.session.commit()


    return jsonify({
        "message": "Token served",
        "token_number": token.token_number
    })

@main.route("/admin/test_next")
def test_next():
    if session.get("role") != "admin":
        return "Not admin", 403

    token = Token.query.filter_by(
        queue_id=1,
        status="ACTIVE"
    ).order_by(Token.created_at.asc()).first()

    if not token:
        return "No active tokens"

    token.status = "SERVED"
    db.session.commit()

    return f"Token {token.token_number} served"


#@main.route("/debug")
#def debug():
    return {
        "user_id": session.get("user_id"),
        "role": session.get("role")
    }

@main.route("/user/token_status")
def user_token_status():
    if not session.get("user_id"):
        return jsonify({"has_token": False})

    token = Token.query.filter(
        Token.user_id == session["user_id"],
        Token.status.in_(["ACTIVE", "SCHEDULED", "PAUSED"])
    ).order_by(Token.created_at.desc()).first()

    # 🚫 NO TOKEN
    if not token:
        return jsonify({"has_token": False})

    now = datetime.utcnow()

    # ⏰ AUTO-RESUME PAUSED TOKEN
    if token.status == "PAUSED":
        if token.postponed_until and now >= token.postponed_until:
            token.status = "ACTIVE"
            token.postponed_until = None
            db.session.commit()
        else:
            return jsonify({
                "has_token": True,
                "status": "PAUSED",
                "token_number": token.token_number
            })

    # 🕒 SCHEDULED TOKEN
    if token.status == "SCHEDULED":
        display_time = token.scheduled_time + timedelta(hours=5, minutes=30)

        return jsonify({
            "has_token": True,
            "status": "SCHEDULED",
            "token_number": token.token_number,
            "scheduled_time": display_time.strftime("%I:%M %p")
        })

    # ✅ ACTIVE TOKEN
    counter = Counter.query.get(token.counter_id)

    people_ahead = Token.query.filter(
        Token.counter_id == token.counter_id,
        Token.status == "ACTIVE",
        Token.created_at < token.created_at
    ).count()

    if people_ahead == 0:
        return jsonify({
            "has_token": True,
            "status": "YOUR_TURN",
            "token_number": token.token_number,
            "counter": counter.counter_number
        })

    wait_time = people_ahead * counter.avg_service_time

    return jsonify({
        "has_token": True,
        "status": "WAITING",
        "token_number": token.token_number,
        "estimated_wait": wait_time
    })

@main.route("/admin/set_queue_settings", methods=["POST"])
def set_queue_settings():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()

    queue_id = data.get("queue_id")
    counters = data.get("counters")
    service_times = data.get("service_times")

    if not queue_id or not counters or not service_times:
        return jsonify({"error": "Invalid input"}), 400

    active_tokens = Token.query.filter_by(
        queue_id=queue_id,
        status="ACTIVE"
    ).count()

    # 🚫 Block optimization if tokens exist
    if active_tokens > 0:
        return jsonify({
            "error": "Cannot change optimization while tokens are active"
        }), 400

    # 🧹 Remove old counters
    Counter.query.filter_by(queue_id=queue_id).delete()

    # ➕ Insert new counters
    for i, time in enumerate(service_times, start=1):
        counter = Counter(
            queue_id=queue_id,
            counter_number=i,
            avg_service_time=time,
            is_active=True
        )
        db.session.add(counter)

    # ⚙️ Update queue settings
    settings = QueueSettings.query.filter_by(queue_id=queue_id).first()
    if not settings:
        settings = QueueSettings(queue_id=queue_id, counters=counters)
        db.session.add(settings)
    else:
        settings.counters = counters

    db.session.commit()

    return jsonify({"message": "Queue optimization saved successfully"})


@main.route("/user/account")
def user_account():
    # 🚫 block admin completely
    if session.get("role") != "user":
        return jsonify({"error": "Unauthorized"}), 403

    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.get(user_id)

    tokens = Token.query.filter_by(user_id=user.id).all()

    history = [{
        "queue": Queue.query.get(t.queue_id).name,
        "token": t.token_number,
        "status": t.status
    } for t in tokens]

    return jsonify({
        "name": user.name,
        "email": user.email,
        "total_tokens": len(tokens),
        "history": history
    })


@main.route("/user/change_password", methods=["POST"])
def change_password():
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    current = data.get("current")
    new = data.get("new")

    user = User.query.get(session["user_id"])

    if not check_password_hash(user.password, current):
        return jsonify({"error": "Current password incorrect"}), 400

    user.password = generate_password_hash(new)
    db.session.commit()

    return jsonify({"message": "Password updated successfully"})

@main.route("/admin/my_queues")
def admin_my_queues():
    if session.get("role") != "admin":
        return jsonify([])

    admin_id = session.get("user_id")

    queues = Queue.query.filter_by(admin_id=admin_id).all()

    return jsonify([
        {"id": q.id, "name": q.name}
        for q in queues
    ])

@main.route("/admin/my_services")
def admin_services():
    if not session.get("user_id"):
        return jsonify([])

    admin_id = session["user_id"]

    services = Queue.query.filter_by(admin_id=admin_id).all()

    return jsonify([
        {"id": q.id, "name": q.name}
        for q in services
    ])

# ---------------- ABOUT PAGE ---------------- #
@main.route("/about")
def about():
    return render_template("about.html")

# ---------------- CONTACT PAGE ---------------- #
@main.route("/contact")
def contact():
    return render_template("contact.html")

@main.route("/user/cancel_token", methods=["POST"])
def cancel_token():
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401

    token = Token.query.filter(
        Token.user_id == session["user_id"],
        Token.status.in_(["ACTIVE", "PAUSED", "SCHEDULED"])
    ).first()

    if not token:
        return jsonify({"error": "No active token"}), 400

    token.status = "CANCELLED"
    db.session.commit()

    return jsonify({
        "message": "Token cancelled",
        "reset": True
    })

@main.route("/user/pause_token", methods=["POST"])
def pause_token():
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401

    token = Token.query.filter_by(
        user_id=session["user_id"],
        status="ACTIVE"
    ).first()

    if not token:
        return jsonify({"error": "No active token"}), 400

    token.status = "PAUSED"
    token.postponed_until = datetime.utcnow() + timedelta(minutes=7)
    db.session.commit()

    return jsonify({"message": "Your turn is postponed by 7 minutes"})

@main.route("/admin/queue_tokens/<int:queue_id>")
def admin_queue_tokens(queue_id):
    if session.get("role") != "admin":
        return jsonify([]), 403

    tokens = (
        db.session.query(Token, User)
        .join(User, Token.user_id == User.id)
        .filter(Token.queue_id == queue_id)
        .order_by(Token.created_at.asc())
        .all()
    )

    result = []

    for token, user in tokens:
        result.append({
            "token_id": token.id,
            "token_number": token.token_number,
            "user_name": user.name,
            "email": user.email,
            "status": token.status,
            "joined_at": token.created_at.strftime("%Y-%m-%d %H:%M"),
            "scheduled_time": token.scheduled_time.strftime("%H:%M") if token.scheduled_time else None,
            "postponed_until": token.postponed_until.strftime("%H:%M") if token.postponed_until else None
        })

    return jsonify(result)

@main.route("/admin/remove_token", methods=["POST"])
def admin_remove_token():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    token_id = data.get("token_id")

    token = Token.query.get(token_id)
    if not token:
        return jsonify({"error": "Token not found"}), 404

    token.status = "CANCELLED"
    db.session.commit()

    return jsonify({"message": "Token removed by admin"})

@main.route("/admin/resume_token", methods=["POST"])
def admin_resume_token():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()
    token_id = data.get("token_id")

    token = Token.query.get(token_id)
    if not token or token.status != "PAUSED":
        return jsonify({"error": "Invalid token"}), 400

    token.status = "ACTIVE"
    token.postponed_until = None
    db.session.commit()

    return jsonify({"message": "Token resumed"})

@main.route("/public/now_serving")
def now_serving():
    active = (
        db.session.query(Token, Queue)
        .join(Queue, Token.queue_id == Queue.id)
        .filter(Token.status == "ACTIVE")
        .order_by(Token.created_at.asc())
        .first()
    )

    if not active:
        return jsonify({"now_serving": None})

    token, queue = active

    return jsonify({
        "queue": queue.name,
        "token_number": token.token_number
    })

from sqlalchemy import func, text
from datetime import datetime

@main.route("/admin/reports")
def admin_reports():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    total_tokens = Token.query.count()

    # ✅ STATUS COUNTS
    status_counts = dict(
        db.session.query(
            Token.status,
            func.count(Token.id)
        ).group_by(Token.status).all()
    )

    served_tokens = status_counts.get("SERVED", 0)
    active_tokens = status_counts.get("ACTIVE", 0)
    cancelled_tokens = status_counts.get("CANCELLED", 0)
    scheduled_tokens = status_counts.get("SCHEDULED", 0)

    # ----- AVG WAIT -----
    served_with_time = Token.query.filter(
        Token.status == "SERVED",
        Token.served_at.isnot(None),
        Token.created_at.isnot(None)
    ).all()

    if served_with_time:
        total_wait = sum(
            (t.served_at - t.created_at).total_seconds()
            for t in served_with_time
        )
        avg_wait = round((total_wait / len(served_with_time)) / 60, 2)
    else:
        avg_wait = 0

    # ----- EFFICIENCY -----
    efficiency = round(
        (served_tokens / total_tokens) * 100, 2
    ) if total_tokens > 0 else 0

    # ----- HOURLY LOAD -----
    hourly_data = (
        db.session.query(
            func.hour(
                func.convert_tz(
                    Token.created_at,
                    '+00:00',
                    '+05:30'
                )
            ).label("hour"),
            func.count(Token.id)
        )
        .group_by("hour")
        .order_by("hour")
        .all()
    )

    hourly = [
        {"hour": h, "count": c}
        for h, c in hourly_data if h is not None
    ]

    return jsonify({
        "total_tokens": total_tokens,
        "served_tokens": served_tokens,
        "active_tokens": active_tokens,
        "cancelled_tokens": cancelled_tokens,
        "scheduled_tokens": scheduled_tokens,
        "avg_wait": avg_wait,
        "efficiency": efficiency,
        "hourly": hourly
    })

@main.route("/admin/dashboard_stats")
def admin_dashboard_stats():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    admin_id = session.get("user_id")

    # 1️⃣ Active Queues (queues assigned to admin)
    active_queues = Queue.query.filter_by(admin_id=admin_id).count()

    # 2️⃣ Total Waiting Tokens (real-time)
    waiting_tokens = Token.query.filter(
        Token.status.in_(["ACTIVE", "PAUSED", "SCHEDULED"])
    ).count()

    # 3️⃣ Average Wait Time (served tokens)
    served_tokens = Token.query.filter(
        Token.status == "SERVED",
        Token.served_at.isnot(None),
        Token.created_at.isnot(None)
    ).all()

    if served_tokens:
        total_wait = sum(
            (t.served_at - t.created_at).total_seconds()
            for t in served_tokens
        )
        avg_wait = round((total_wait / len(served_tokens)) / 60, 2)
    else:
        avg_wait = 0

    #  Efficiency
    total_tokens = Token.query.count()
    efficiency = round(
        (len(served_tokens) / total_tokens) * 100, 2
    ) if total_tokens > 0 else 0

    return jsonify({
        "active_queues": active_queues,
        "waiting_tokens": waiting_tokens,
        "avg_wait": avg_wait,
        "efficiency": efficiency
    })

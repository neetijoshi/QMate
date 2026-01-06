from datetime import datetime
from . import db
from sqlalchemy import JSON

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="user")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Queue(db.Model):
    __tablename__ = "queues"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    status = db.Column(db.String(50), default="Active")

    admin_id = db.Column(db.Integer, db.ForeignKey("users.id"))  # ✅ NEW

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    queue_id = db.Column(db.Integer, db.ForeignKey("queues.id"), nullable=False)

    counter_id = db.Column(db.Integer, db.ForeignKey("counters.id"))

    token_number = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default="ACTIVE")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)


class QueueSettings(db.Model):
    __tablename__ = "queue_settings"

    id = db.Column(db.Integer, primary_key=True)
    queue_id = db.Column(db.Integer, db.ForeignKey("queues.id"))

    # NEW
    counter_service_times = db.Column(JSON)  
    # Example: { "1": 5, "2": 3, "3": 2 }

    counters = db.Column(db.Integer)

class Counter(db.Model):
    __tablename__ = "counters"

    id = db.Column(db.Integer, primary_key=True)
    queue_id = db.Column(db.Integer, db.ForeignKey("queues.id"), nullable=False)
    counter_number = db.Column(db.Integer, nullable=False)
    avg_service_time = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

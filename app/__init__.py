from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:joshineeti@localhost/qmate_db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = "qmate_secret_key"

    db.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import Queue
        db.create_all()

        # seed queues only once
        if Queue.query.count() == 0:
            db.session.add_all([
                Queue(name="Billing"),
                Queue(name="General Helpdesk"),
                Queue(name="Document Verification")
            ])
            db.session.commit()

    return app

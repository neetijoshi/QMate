from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    # ✅ MySQL Workbench connection
    app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:joshineeti@localhost/qmate_db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = "qmate_secret_key"

    db.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    # ✅ create tables
    with app.app_context():
        db.create_all()

    return app

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from os import path
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initializing SQLAlchemy object
db = SQLAlchemy()
csrf = CSRFProtect()  # Initialize CSRF protection
DB_NAME = "netflowinsight.db"

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,  # Use the client's IP address for rate limiting
    default_limits=["200 per day", "50 per hour"],  # Default limits for all routes
)


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = "SECRET"
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Set session lifetime to 30 minutes
    db.init_app(app)
    csrf.init_app(app)  # Enable CSRF protection globally
    limiter.init_app(app)  # Attach the limiter to the app

    from .views import views
    from .auth import auth
    from .models import User, PcapLoc, FileAnalysis, Notes, FileResult

    # Blueprints for different parts of the app
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    with app.app_context():
        try:
            if not path.exists('instance/' + DB_NAME):
                db.create_all()
                print("--- Database Created ---")
        except Exception as e:
            print(f"{e}")

    # Initializing the LoginManager for managing user sessions
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    # Loading a user based on the provided user ID
    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    # Returning the configured app
    return app
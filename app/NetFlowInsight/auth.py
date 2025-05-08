from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os, random, re
from bleach import clean  # For sanitizing user input
from password_strength import PasswordPolicy  # For enforcing password strength

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,  # Use the client's IP address for rate limiting
    default_limits=["200 per day", "50 per hour"],  # Default limits for all routes
)

# Password strength policy
policy = PasswordPolicy.from_names(
    length=8,  # Minimum length: 8 characters
    uppercase=1,  # At least 1 uppercase letter
    numbers=1,  # At least 1 number
    special=1,  # At least 1 special character
    nonletters=1,  # At least 1 non-letter (number or special character)
)

# Creating a Blueprint named 'auth'
auth = Blueprint('auth', __name__)


# Route for user signup
@auth.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Retrieve and sanitize form data
        email = clean(request.form.get('email'))
        firstname = clean(request.form.get('firstname'))
        lastname = clean(request.form.get('lastname'))
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # Validate email format
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            flash('Invalid email format.', category='error')
            return render_template("signup.html", user=current_user)

        # Check for existing user with the same email
        user_exists = User.query.filter_by(email=email).first()

        # Validate user input
        if len(firstname) < 2:
            flash('Firstname must be longer than 1 character.', category='error')
        elif len(lastname) < 2:
            flash('Lastname must be longer than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords do not match.', category='error')
        elif user_exists:
            flash('A user with this email already exists! Please choose another email.', category='error')
        else:
            # Enforce password strength
            password_issues = policy.test(password1)
            if password_issues:
                flash('Password must be at least 8 characters long, include an uppercase letter, a number, and a special character.', category='error')
            else:
                try:
                    # Create a unique user identifier
                    user = firstname + "_" + str(random.random())

                    # Create a unique directory for each user's files
                    base_directory = os.path.abspath('/opt/uploads/Files')
                    user_directory = os.path.join(base_directory, user)
                    if not os.path.exists(user_directory):
                        os.makedirs(user_directory)

                    # Create a new user object and add it to the database
                    new_user = User(
                        email=email,
                        firstname=firstname,
                        lastname=lastname,
                        password=generate_password_hash(password1, method='pbkdf2:sha256'),
                        path=user_directory,
                    )
                    db.session.add(new_user)
                    db.session.commit()

                    flash('Account created successfully!', category='success')
                    return redirect(url_for('auth.login'))

                except Exception as e:
                    flash(f'Error: {e}', category='error')

    return render_template("signup.html", user=current_user)


# Route for user login with rate limiting
@auth.route("/login", methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit to 5 login attempts per minute per IP
def login():
    if request.method == 'POST':
        # Retrieve and sanitize form data
        email = clean(request.form.get('email'))
        password = request.form.get('password')

        # Query the database for the user with the provided email
        user = User.query.filter_by(email=email).first()

        # Validate user credentials
        if user and check_password_hash(user.password, password):
            flash('Logged in successfully!', category='success')
            login_user(user, remember=True)
            return redirect(url_for('views.home', user=current_user))
        else:
            flash('Username or password incorrect!', category='error')

    return render_template("login.html", user=current_user)

# Route for user logout
@auth.route("logout/")
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', category='success')
    return redirect(url_for('auth.login'))
import json
import os
from datetime import datetime, timedelta, date
from flask_bcrypt import Bcrypt
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import requests
from flask import Flask, render_template, redirect, url_for, flash, abort, request, current_app, jsonify, make_response, Response, send_from_directory, send_file
from sqlalchemy.orm import joinedload
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_babel import Babel
from werkzeug.utils import secure_filename
from models import db, User, bcrypt, Seller, Product
from forms import RegistrationForm, LoginForm, ProductForm
from flask_wtf import CSRFProtect



app = Flask(__name__)
babel = Babel(app)
csrf = CSRFProtect(app)



# Load the configuration
app.config.from_object('config.Config')

# Initialize the extensions
db.init_app(app)
bcrypt.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

with app.app_context():
    db.create_all()

# Define the user loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class MyModelView(ModelView):
    def is_accessible(self):
        return True

# Initialize Flask-Admin
admin = Admin(app)
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Product, db.session))
admin.add_view(MyModelView(Seller, db.session))

@app.route("/")
@app.route("/home")
def home():
    return render_template("index.html")


@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = form.password.data
        phone_number = form.phone_number.data
        gender = form.gender.data
        role = form.role.data

        # Check if a user with the same email or username already exists
        existing_user_email = User.query.filter_by(email=email).first()
        existing_user_username = User.query.filter_by(username=username).first()
        if existing_user_email or existing_user_username:
            flash('User with the same email or username already exists. Please choose a different email or username.',
                  'danger')
            return redirect(url_for('register'))

        new_user = User(email=email, username=username, phone_number=phone_number, gender=gender, role=role)
        new_user.set_password(password)  # Ensure this line correctly hashes the password

        db.session.add(new_user)
        db.session.commit()

        if new_user.role == "seller":
            new_seller = Seller(email=email, date_registered=datetime.utcnow(), phone_number=phone_number)
            db.session.add(new_seller)
            db.session.commit()

        flash('Your account has been created!', 'success')

        # Debug print statement to check redirect URL
        print(f"Redirecting to: {url_for('login')}")

        return redirect(url_for('login'))

    return render_template("register.html", form=form)


@app.route("/login", methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            if user.role == "user":
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            elif user.role == "admin":
                return redirect(url_for('dashboard'))
            elif user.role == "seller":
                # Correct the following line by adding parentheses to call the 'first' method
                seller = Seller.query.filter_by(email=user.email).first()
                if seller and seller.authenticated:
                    return redirect(url_for('dashboard'))
                else:
                    return redirect(url_for('pending'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')

    return render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/pending")
@login_required
def pending():
    # Check if the current user is a seller and their account is not authenticated yet
    if current_user.role == 'seller':
        # Correct the following line by adding parentheses to call the 'first' method
        seller = Seller.query.filter_by(email=current_user.email).first()
        if seller and seller.authenticated:
            return redirect(url_for('home'))
        else:
            return render_template("pending.html")

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        return render_template("admin_dashboard.html")
    elif current_user.role == "seller":
        seller = Seller.query.filter_by(email=current_user.email).first()
        if seller and seller.authenticated:
            return render_template("seller_dashboard.html")
        else:
            return redirect(url_for('pending'))
    if current_user.role == "user":
        return render_template("user_dashboard.html")
    else:
        return redirect(url_for('home'))

@app.route("/seller_requests")
@login_required
def seller_requests():
    if current_user.role != 'admin':
        abort(403)
    sellers = Seller.query.filter_by(authenticated=False).all()
    return render_template("seller_requests.html", sellers=sellers)


@app.route('/approve_seller/<int:seller_id>', methods=['POST'])
@login_required
@csrf.exempt  # If needed, you can also add this decorator to exempt the route from CSRF protection
def approve_seller(seller_id):
    if current_user.role != 'admin':
        abort(403)
    seller = Seller.query.get_or_404(seller_id)
    if seller.authenticated:
        return jsonify({'status': 'error', 'message': 'Seller already approved'})
    seller.authenticated = True
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Seller approved'})

@app.route('/reject_seller/<int:seller_id>', methods=['POST'])
@login_required
def reject_seller(seller_id):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized access.'}), 403

    seller = Seller.query.get(seller_id)
    if not seller:
        return jsonify({'status': 'error', 'message': 'Seller not found.'}), 404

    user = User.query.filter_by(email=seller.email).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    try:
        db.session.delete(seller)
        db.session.delete(user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Seller rejected and user account deleted successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500



if __name__ == "__main__":
    app.run(debug=True)

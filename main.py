import json
import os
from werkzeug.utils import secure_filename
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
from models import db, User, bcrypt, Seller, Product, Order
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
admin.add_view(MyModelView(Order, db.session))


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
            orders = Order.query.filter_by(seller_id=current_user.id).order_by(Order.date.desc()).all()
            return render_template('seller_dashboard.html', orders=orders)
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


@app.route("/add_product", methods=["GET", "POST"])
@login_required
def add_product():
    if current_user.role != 'seller':
        abort(403)  # Only sellers can access this route

    # Fetch the seller associated with the current user
    seller = Seller.query.filter_by(email=current_user.email).first()

    # Check if the seller is authenticated
    if seller and seller.authenticated:
        form = ProductForm()

        if form.validate_on_submit():
            product_name = form.name.data
            price = form.price.data
            category = form.category.data
            stock = form.stock.data
            color = form.color.data
            seller_id = seller.id

            # Handle image uploads
            image1 = form.image1.data
            image2 = form.image2.data
            image3 = form.image3.data
            image4 = form.image4.data

            image1_filename = secure_filename(image1.filename) if image1 else None
            image2_filename = secure_filename(image2.filename) if image2 else None
            image3_filename = secure_filename(image3.filename) if image3 else None
            image4_filename = secure_filename(image4.filename) if image4 else None

            # Save the images to the upload folder
            if image1:
                image1.save(os.path.join(current_app.config['UPLOAD_FOLDER'], image1_filename))
            if image2:
                image2.save(os.path.join(current_app.config['UPLOAD_FOLDER'], image2_filename))
            if image3:
                image3.save(os.path.join(current_app.config['UPLOAD_FOLDER'], image3_filename))
            if image4:
                image4.save(os.path.join(current_app.config['UPLOAD_FOLDER'], image4_filename))

            # Create a new Product object
            product = Product(
                name=product_name,
                price=price,
                category=category,
                stock=stock,
                color=color,
                seller_id=seller_id,
                user_id = current_user.id,
                image1=image1_filename,
                image2=image2_filename,
                image3=image3_filename,
                image4=image4_filename
            )

            # Add and commit the new product to the database
            db.session.add(product)
            db.session.commit()

            flash('Product has been added!', 'success')
            return redirect(url_for('dashboard'))

        return render_template("add_product.html", form=form)
    else:
        return redirect(url_for('pending'))  # Redirect to the pending page if the seller is not authenticated


@app.route('/my_products')
@login_required
def my_products():
    if current_user.role != 'seller':
        abort(403)
    seller = Seller.query.filter_by(email=current_user.email).first()
    if seller and seller.authenticated:
        products = Product.query.filter_by(seller_id=seller.id).all()
        return render_template('my_products.html', products=products)
    else:
        return redirect(url_for('pending'))



@app.route('/product_requests')
@login_required
def product_requests():
    if current_user.role != 'admin':
        abort(403)

    # Query products that need admin approval
    products = Product.query.filter_by(authenticated=False).all()

    # Create a dictionary to map product IDs to seller emails
    seller_emails = {}

    for product in products:
        seller = Seller.query.get(product.seller_id)
        seller_emails[product.id] = seller.email if seller else 'Unknown'
    print(seller_emails)
    return render_template("product_requests.html", products=products, seller_emails=seller_emails)


@app.route('/approve_product/<int:product_id>', methods=['POST'])
@login_required
def approve_product(product_id):
    if current_user.role != 'admin':
        abort(403)
    product = Product.query.get_or_404(product_id)
    if product.authenticated:
        return jsonify({'status': 'error', 'message': 'Product already approved'})
    product.authenticated = True
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Product approved'})

@app.route('/reject_product/<int:product_id>', methods=['POST'])
@login_required
def reject_product(product_id):
    if current_user.role != 'admin':
        return jsonify({'status': 'error', 'message': 'Unauthorized access.'}), 403

    product = Product.query.get(product_id)
    if not product:
        return jsonify({'status': 'error', 'message': 'Product not found.'}), 404

    try:
        db.session.delete(product)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Product rejected and removed successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/view_details/<int:product_id>')
@login_required
def view_details(product_id):
    product = Product.query.get_or_404(product_id)
    if current_user.role == 'seller':
        return render_template('view_details_seller.html', product=product)
    elif current_user.role == 'admin':
        return render_template('view_details_admin.html', product=product)
    elif current_user.role == 'user':
        return render_template('view_details_user.html', product=product)
    else:
        abort(403)  # Forbidden


if __name__ == "__main__":
    app.run(debug=True)

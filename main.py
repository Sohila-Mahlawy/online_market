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
from models import db, User, bcrypt, Seller, Product, Order, Category, Cart
from forms import RegistrationForm, LoginForm, ProductForm, CategoryForm
from flask_wtf import CSRFProtect




app = Flask(__name__)
babel = Babel(app)
csrf = CSRFProtect(app)
csrf.init_app(app)



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
admin.add_view(MyModelView(Category, db.session))
admin.add_view(MyModelView(Cart, db.session))



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
        categories = Category.query.all()
        return render_template('user_dashboard.html', categories=categories)
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



from flask import render_template, redirect, url_for, flash
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename
import os


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
            category_id = form.category.data
            stock = form.stock.data
            color = form.color.data
            seller_id = seller.id

            # Fetch the category from the database
            category = Category.query.get(category_id)

            # Check if the price exceeds the category's maximum price
            if price > category.price:
                flash(f'The product could not be saved because the maximum price for the category "{category.name}" is {category.price}.', 'danger')
                return render_template("add_product.html", form=form)

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
                category=category.name,
                stock=stock,
                color=color,
                seller_id=seller_id,
                user_id=current_user.id,
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


@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if current_user.role not in ["admin", "seller"]:
        abort(403)  # Only admins or sellers can access this route

    form = ProductForm(obj=product)

    if form.validate_on_submit():
        # Validate price against category price
        category = Category.query.get(form.category.data)
        if form.price.data > category.price:
            form.price.errors.append(f"Price cannot exceed the category price of {category.price}.")
            return render_template('edit_product.html', form=form, product=product, user=current_user)

        # Update product details
        product.name = form.name.data
        product.price = form.price.data
        product.category = category.name
        product.stock = form.stock.data
        product.color = form.color.data

        # Handle image uploads
        image1 = form.image1.data
        image2 = form.image2.data
        image3 = form.image3.data
        image4 = form.image4.data

        if image1:
            product.image1 = secure_filename(image1.filename)
            image1.save(os.path.join(current_app.config['UPLOAD_FOLDER'], product.image1))
        if image2:
            product.image2 = secure_filename(image2.filename)
            image2.save(os.path.join(current_app.config['UPLOAD_FOLDER'], product.image2))
        if image3:
            product.image3 = secure_filename(image3.filename)
            image3.save(os.path.join(current_app.config['UPLOAD_FOLDER'], product.image3))
        if image4:
            product.image4 = secure_filename(image4.filename)
            image4.save(os.path.join(current_app.config['UPLOAD_FOLDER'], product.image4))

        # Commit changes to the database
        db.session.commit()
        flash('Product has been updated!', 'success')

        if current_user.role == "admin":
            return redirect("/product_categories")
        elif current_user.role == "seller":
            return redirect(url_for('my_products'))

    return render_template('edit_product.html', form=form, product=product, user=current_user)


@app.route('/delete_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    if current_user.role == "user":
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully.', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting product: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))



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
    seller_email = 'Unknown'

    # Fetch the seller email for the product
    seller = Seller.query.get(product.seller_id)
    seller_email = seller.email

    if current_user.role == 'seller':
        return render_template('product_details_seller.html', product=product, seller_email=seller_email)
    elif current_user.role == 'admin':
        return render_template('product_details_admin.html', product=product, seller_email=seller_email)
    elif current_user.role == 'user':
        return render_template('product_details_user.html', product=product, seller_email=seller_email)
    else:
        abort(403)  # Forbidden


@app.route('/categories', methods=['GET', 'POST'])
@login_required
def manage_categories():
    if current_user.role != 'admin':
        abort(403)  # Only admins can access this route

    form = CategoryForm()
    categories = Category.query.all()

    if form.validate_on_submit():
        category_name = form.name.data
        category_price = form.price.data

        # Check if a category with the same name already exists
        existing_category = Category.query.filter_by(name=category_name).first()
        if existing_category:
            flash('Category with the same name already exists. Please choose a different name.', 'danger')
        else:
            # Create a new Category object
            new_category = Category(name=category_name, price=category_price)
            db.session.add(new_category)
            db.session.commit()
            flash('Category has been added!', 'success')
            return redirect(url_for('manage_categories'))

    return render_template('categories.html', form=form, categories=categories)



@app.route("/product_categories")
def product_categories():
    categories = Category.query.all()
    role_based_template = 'user_base.html'

    # Determine the correct base template based on the user's role
    if current_user.role == 'admin':
        role_based_template = 'admin_base.html'
    elif current_user.role == 'seller':
        role_based_template = 'seller_base.html'

    return render_template("product_categories.html", user=current_user, categories=categories,
                           base_template=role_based_template)


@app.route('/products/<category_name>')
def category_products(category_name):
    products = Product.query.filter_by(category=category_name).all()
    return render_template('products.html', products=products, category_name=category_name, user=current_user)


from datetime import datetime


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
@csrf.exempt
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)

    # Check if product is already in the cart
    existing_item = Cart.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if existing_item:
        return jsonify({'message': 'Product is already in your cart.'})
    else:
        new_cart_item = Cart(user_id=current_user.id, product_id=product_id, date_added=datetime.utcnow())
        db.session.add(new_cart_item)
        db.session.commit()
        return jsonify({'message': 'Product added to cart!'})


@app.route('/cart')
@login_required
def cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    products = [Product.query.get(item.product_id) for item in cart_items]
    return render_template('cart.html', cart_items=cart_items, products=products)


@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    try:
        # Check if the product and user ID are valid
        if not product_id:
            raise ValueError('Invalid product ID.')

        cart_item = Cart.query.filter_by(product_id=product_id, user_id=current_user.id).first()

        if not cart_item:
            app.logger.warning(f'Item with product_id {product_id} not found in cart for user_id {current_user.id}')
            return jsonify({'status': 'error', 'message': 'Item not found in cart'}), 404

        db.session.delete(cart_item)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Item removed from cart'})

    except ValueError as e:
        app.logger.error(f'ValueError: {e}')
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Failed to remove item from cart: {e}')
        return jsonify({'status': 'error', 'message': 'Failed to remove item from cart'}), 500


@app.route('/order', methods=['POST'])
@login_required
def order():
    # Implement order logic here
    flash('Order placed successfully', 'success')
    return redirect(url_for('cart'))

if __name__ == "__main__":
    app.run(debug=True)

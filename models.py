from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(100), unique=True)
    phone_number = db.Column(db.String(1000), unique=True)
    gender = db.Column(db.String(100))
    role = db.Column(db.String(100), default="user")
    orders = db.relationship('Order', backref='buyer', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)



class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('seller.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    delivery_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(50), nullable=False, default="pending")
    user_email = db.Column(db.String(100), nullable=False)

class Seller(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    authenticated = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(15), nullable=True)
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    products = db.relationship('Product', backref='owner_seller', lazy=True)
    orders = db.relationship('Order', backref='seller', lazy=True)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    color = db.Column(db.String(1000))
    category = db.Column(db.String(100), nullable=False)
    image1 = db.Column(db.String(120), nullable=True)
    image2 = db.Column(db.String(120), nullable=True)
    image3 = db.Column(db.String(120), nullable=True)
    image4 = db.Column(db.String(120), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('seller.id'), nullable=False)
    orders = db.relationship('Order', backref='product', lazy=True)
    authenticated = db.Column(db.Boolean, default=False)

    @staticmethod
    def add(name, price, stock, category, user_id, seller_id, image1=None, image2=None, image3=None, image4=None):
        new_product = Product(name=name, price=price, stock=stock, category=category, user_id=user_id, seller_id=seller_id, image1=image1, image2=image2, image3=image3, image4=image4)
        db.session.add(new_product)
        db.session.commit()

    def buy(self, user_id):
        if self.stock > 0:
            self.stock -= 1
            order = Order(user_id=user_id, product_id=self.id, seller_id=self.seller_id)
            db.session.add(order)
            db.session.commit()
            return True, "Purchase successful!"
        return False, "Product out of stock."


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    price = db.Column(db.Integer, nullable=True)
    def __repr__(self):
        return f'<Category {self.name}>'


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship('User', backref='cart_items', lazy=True)
    product = db.relationship('Product', backref='cart_items', lazy=True)

    def __repr__(self):
        return f'<Cart {self.user_id} {self.product_id}>'

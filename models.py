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
    purchases = db.relationship('Purchase', backref='buyer', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_user_purchases(self):
        return Purchase.query.filter_by(user_id=self.id).all()

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('seller.id'), nullable=False)
    purchases = db.relationship('Purchase', backref='product', lazy=True)

    @staticmethod
    def add(name, price, stock, user_id, seller_id):
        new_product = Product(name=name, price=price, stock=stock, user_id=user_id, seller_id=seller_id)
        db.session.add(new_product)
        db.session.commit()

    def buy(self, user_id):
        if self.stock > 0:
            self.stock -= 1
            purchase = Purchase(user_id=user_id, product_id=self.id)
            db.session.add(purchase)
            db.session.commit()
            return True, "Purchase successful!"
        return False, "Product out of stock."

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Seller(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    authenticated = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(15), nullable=True)
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    products = db.relationship('Product', backref='owner_seller', lazy=True)

from flask_wtf import FlaskForm
from wtforms import StringField, DecimalField, SubmitField, IntegerField, PasswordField, SelectField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, NumberRange
from flask_wtf.file import FileAllowed
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('female', 'Female'), ('male', 'Male')], validators=[DataRequired()])
    role = SelectField('Role', choices=[('user', 'User'), ('seller', 'Seller')], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired(), NumberRange(min=0.01)])
    category = SelectField('Category', choices=[('electronics', 'Electronics'), ('fashion', 'Fashion'), ('home', 'Home'), ('toys', 'Toys'), ('books', 'Books')], validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired(), NumberRange(min=1)])
    image1 = FileField('Image 1', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    image2 = FileField('Image 2', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    image3 = FileField('Image 3', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    image4 = FileField('Image 4', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    submit = SubmitField('Add Product')

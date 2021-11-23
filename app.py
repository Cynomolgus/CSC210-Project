from flask import Flask, render_template, url_for, redirect, request, flash, session
from random import randint
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, \
SubmitField
from wtforms.validators import DataRequired, Length, Email
from flask_login import LoginManager, login_user, logout_user
from flask_mail import Mail,Message
from werkzeug.security import generate_password_hash , check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SECRET_KEY'] = 'hard to guess string'
app.config [ 'SQLALCHEMY_TRACK_MODIFICATIONS' ] = False
db = SQLAlchemy(app)
mail = Mail(app)
app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] =465
app.config["MAIL_USERNAME"] ='dagidadagi@gmail.com'
app.config["MAIL_PASSWORD"] ='dagi1234'
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True
mail = Mail(app)
otp=randint(000000,999999)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))

    def __repr__(self):
        return f"User('{self.email}','{self.password}')"

    @property
    def password(self):
        raise AttributeError ("pwd not a readable attribute")

    @password.setter
    def password(self , password):
        self. password_hash = generate_password_hash (password)

    def verify_password (self , password ):
        return check_password_hash (self.password_hash, password)

@ app.route('/')
def index():
    return render_template('index.html')

@ app.route('/register', methods = ['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit(): 
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            return redirect(url_for('dashboard'))
        msg = Message(subject='OTP',sender='dagidadagi@gmail.com',recipients=[form.email.data])
        msg.body=str(otp)
        mail.send(msg)
        new_user = User(email = form.email.data, password = form.password.data, username = form.username.data)
        return redirect(url_for('OTP', user = new_user))
    return render_template('register.html', form = form)

@ app.route('/register/OTP', methods = ['GET','POST'])
def OTP():
    user = request.user
    form = OTPForm()
    
    if form.validate_on_submit():
        if otp == int(form.OTP.data):
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('verify.html', form = form)

@ app.route('/login', methods = ['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            session['curr_email'] = form.email.data  
            if form.remember_me.data:
                login_user(user, remember=True, duration=timedelta(days=1))  
            login_user(user, remember=False)
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    flash('You have been logged out.')
    logout_user()
    return redirect(url_for('index'))

@ app.route('/dashboard', methods = ['GET','POST'])
@login_required
def dashboard():
    curr_email = session['curr_email']
    return render_template('main.html', email = curr_email)

@ app.route('/reset', methods = ['GET','POST'])
def reset():
    return render_template('reset.html')

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(1, 64), Email()], render_kw={"placeholder": "Enter your UR email"})
    username = StringField("Email", validators=[DataRequired(), Length(1, 64)], render_kw={"placeholder": "Enter your Username"})
    password = PasswordField("Password", validators=[DataRequired()], render_kw={"placeholder": "Enter your password"})
    submit = SubmitField("Register")
   
  
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Length(1, 64), Email()], render_kw={"placeholder": "Enter your UR email"})
    password = PasswordField("Password", validators=[DataRequired()], render_kw={"placeholder": "Enter your password"})
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log In")

class OTPForm(FlaskForm):
    OTP = StringField("OTP",  render_kw={"placeholder": "Enter the OTP"})
    OTP_send = SubmitField("Submit")

if __name__ =='__main__': 
    app.run(debug = True)
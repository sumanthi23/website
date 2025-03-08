from flask import Flask, render_template,redirect, url_for,flash,request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,PasswordField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_session import Session
from app import db, Users

# Create a test user
new_user = Users(username="Alice", email="alice@example.com")
new_user.set_password("password123")

# Add to database
with db.session.begin():
    db.session.add(new_user)

print("✅ Sample user added successfully!")




app = Flask(__name__)

# Add database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' 
app.config['SECRET_KEY'] = "myflaskapp"
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
Session(app)

with app.app_context():
    db.create_all()
 
# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



# Create model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # Fixed typo "primar_key"
    username = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)  # Fixed "string" to "String"
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(256), nullable = False)
    
    def __repr__(self):  # Fixed "__repe__" to "__repr__"
        return f'<User {self.username}>'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Form class
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# User Loader (Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class UserForm(FlaskForm):
    username = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("password",validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message="Passwords must match")])
    submit = SubmitField("Add User")

class UpdateForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    old_password = PasswordField("Old Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired()])
    def check_password(self, Old_password):
        return check_password_hash(self.password_hash, Old_password)
    submit = SubmitField("Update")
# Routes'''
@app.route("/")
def index():
    return render_template('index.html')

@app.route("/user/add", methods=["GET", "POST"])
def add_user():
    users = Users.query.order_by(Users.id).all()
    return render_template("add_user.html",users=users)

@app.route("/update/<int:id>", methods=["GET", "POST"])
def update(id):
    user = Users.query.get_or_404(id)  
    form = UpdateForm()
    if form.validate_on_submit():
        user.username = form.username.data  
        user.email = form.email.data
        if user.check_password(form.old_password.data):  
            if form.new_password.data:
                user.set_password(form.new_password.data)
        db.session.commit()
        flash("User updated successfully!", "success")
        return redirect(url_for('login'))
    else:
        print(" Form validation failed!", form.errors) 
    form.username.data = user.username
    form.email.data = user.email
    form.new_password.data=user.password_hash
    return render_template("update.html", form=form, user=user)  


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == "POST":  
        print("Form Data Received:", request.form)
        print("Validation Success:", form.validate_on_submit())
        print("Errors:", form.errors) 
        
    if form.validate_on_submit():
        existing_user = Users.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        new_user = Users(username=form.username.data, email=form.email.data)
        if not form.password.data: 
            flash("Password cannot be empty!", "danger")
            return redirect(url_for('register'))
        new_user.set_password(form.password.data)

    try:
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        db.session.rollback()
        flash("An error occurred. Please try again.", "danger")

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            print(f"Logged in: {current_user}")
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    print(f"Current user: {current_user}")
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True) 
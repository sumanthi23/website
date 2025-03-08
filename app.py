from flask import Flask, render_template,redirect, url_for,flash,request,session
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,PasswordField,FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_session import Session
from flask_wtf.file import FileAllowed
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' 
app.config['SECRET_KEY'] = "myflaskapp"
app.config['UPLOAD_FOLDER'] = "static/images/"
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"
app.config['SESSION_COOKIE_SECURE'] = True
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

db = SQLAlchemy(app)
migrate = Migrate(app, db)
Session(app)

with app.app_context():
    db.create_all()
 

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'




class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  
    username = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)  
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(256), nullable = False)
    profile_pic = db.Column(db.String(200), nullable=True, default="default_profile_pic.png")
    
    def __repr__(self):  
        return f'<User {self.username}>'
    
    def profile_picture_path(self):
        return url_for('static', filename='images/' + self.profile_pic)
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class ProfilePicForm(FlaskForm):
    profile_pic = FileField("Update Profile Picture", validators=[
        FileAllowed(['jpg', 'png', 'jpeg'], 'Only images are allowed!'),
        DataRequired()
    ])
    submit = SubmitField("Upload")

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
    submit = SubmitField("Update")
class AdminForm(FlaskForm):
    username = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    id = db.Column(db.Integer, primary_key=True)
# Routes'''
@app.route("/index")
def index():
    return render_template('index.html')

@app.route("/admin", methods=["GET", "POST"])
def admin():
    users = Users.query.order_by(Users.date_added).all()
    return render_template("admin.html", users=users)

@app.route('/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_user(id):
    if current_user.id !=9: 
        flash("Unauthorized! Only the admin can delete users.", "danger")
        return redirect(url_for('admin'))  

    user_to_delete = Users.query.get_or_404(id)  
    if user_to_delete.id == 9:  
        flash("Admin account cannot be deleted!", "danger")
        return redirect(url_for('admin'))

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f"User {user_to_delete.username} deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting user: {str(e)}", "danger")

    return redirect(url_for('admin'))


@app.route("/update/<int:id>", methods=["GET", "POST"])
@login_required
def update(id):
    user = Users.query.get_or_404(id)  
    form = UpdateForm()
    if form.validate_on_submit() and request.method == 'POST':
        if user.verify_password(form.old_password.data):  
            user.username = form.username.data  
            user.email = form.email.data
            if form.new_password.data:
                user.set_password(form.new_password.data)
                db.session.commit()
                flash("User updated successfully!", "success")
                return redirect(url_for('login'))
        else:
            flash("Old password is incorrect!", "danger")
    
    elif request.method=='GET':
        form.username.data = user.username
        form.email.data = user.email
    return render_template("update.html", form=form, user=user)  


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = Users.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return redirect(url_for('register'))
        
        new_user = Users(username=form.username.data, email=form.email.data)
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

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user and user.verify_password(form.password.data):
            login_user(user)
            session.permanent=True
            session['user_id'] = user.id  
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password!', 'danger')

    return render_template('login.html', form=form)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_profile', methods=['GET', 'POST'])
@login_required
def upload_profile():
    if request.method == 'POST':
        file = request.files.get('profile_pic') 
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            file.save(file_path)  

            
            current_user.profile_pic = filename
            db.session.commit()

            flash("Profile picture updated!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid file type! Please upload a PNG, JPG, or JPEG.", "danger")

    return render_template("upload.html")

@app.route('/dashboard')
@login_required
def dashboard():
    profile_pic = current_user.profile_pic if current_user.profile_pic else 'default_profile.png'
    return render_template('dashboard.html', user=current_user, profile_pic=profile_pic)
    

@app.route('/check_session')
def check_session():
      return f"Session Data: {dict(session)}"

@app.route('/logout')
@login_required
def logout():
    session.clear() 
    logout_user()  
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=True) 
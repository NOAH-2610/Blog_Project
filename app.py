from flask import Flask, render_template, redirect, url_for, request, flash
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from bson.objectid import ObjectId
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.secret_key = os.getenv("SECRET_KEY")


mongo = PyMongo(app)
login_manager = LoginManager()
login_manager.login_view = 'login' #Redirect to login page
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']

@login_manager.user_loader
def load_user(user_id):
    user_data  = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash("Passwords do not match!")
            return redirect(url_for('register'))
        
        existing_user = mongo.db.users.find_one({
            "$or": [{"username":username},{"email":email}]
        })

        if existing_user:
            flash("Username or email already exists!")
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(password)

        new_user = {
            "username":username,
            "email":email,
            "password":hashed_pw,
            "created_at":datetime.utcnow()
        }

        mongo.db.users.insert_one(new_user)
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')

        user_data = mongo.db.users.find_one({"username":username})
        if user_data:
            if check_password_hash(user_data['password'],password):
                user = User(user_data)
                login_user(user)
                flash("Login Successful!")
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect Password.")
        else:
            flash("User not found.")
        
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out!")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return f"Welcome, {current_user.username}!!"

@app.route('/')
def index():
    return "<h1>Welcome to the Flask Blog Platform!</h1>"


if __name__ == '__main__':
    app.run(debug=True)
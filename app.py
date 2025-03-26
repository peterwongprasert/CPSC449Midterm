from flask import Flask, render_template, request, redirect, url_for, make_response, session, flash, jsonify, send_from_directory
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import jwt
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

# Configuration
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret')
app.config['UPLOADS'] = 'uploads'
app.config['EXTENSIONS'] = ['.jpg', '.jpeg', '.png']
JWT_SECRET = os.getenv('JWT_SECRET', 'my_secret_jwt_key')
JWT_EXPIRATION = timedelta(hours=1)  # 1 hour

# Initialize PyMongo (assuming MongoDB is used)
app.config["MONGO_URI"] = os.getenv('MONGO_URI', "mongodb://localhost:27017/your_database")
mongo = PyMongo(app)
user_collection = mongo.db.users

# Helper function to generate JWT token
def generate_token(username):
    payload = {
        "username": username,
        "exp": datetime.utcnow() + JWT_EXPIRATION
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

# Route for uploading files
@app.route('/sendFile/<id>', methods=['POST', 'GET'])
def sendFile(id):
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = secure_filename(uploaded_file.filename)
            if os.path.splitext(filename)[1] in app.config['EXTENSIONS']:
                uploaded_file.save(os.path.join(app.config['UPLOADS'], filename))
                update_user_picture(filename, id)  # Update profile picture in DB
                flash('File uploaded successfully', 'success')
            else:
                flash('Invalid file extension. Please upload .jpg, .jpeg, or .png', 'error')
        else:
            flash('No file selected.', 'error')
    return redirect(url_for('profile'))

# Update user's profile picture in DB
def update_user_picture(filename, user_id):
    result = user_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"picture": filename}}
    )
    if result.matched_count > 0:
        return jsonify({"message": "User picture updated successfully"})
    else:
        return jsonify({"error": "User not found"}), 404

# Route for displaying profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    token = request.cookies.get('jwt')
    if not token:
        flash('You are not logged in.', 'error')
        return redirect(url_for('login'))

    try:
        user_data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        print(f"User data: {user_data}")  # Debugging line

        user = user_collection.find_one({"username": user_data['username']})
        if user:
            return render_template('profile.html', user=user)
        else:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
    except jwt.ExpiredSignatureError:
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        flash('Invalid token. Please log in again.', 'error')
        return redirect(url_for('login'))

# Route for logging out
@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('jwt')
    flash('Logged out successfully.', 'success')
    return resp

# Route for login
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate login credentials (this should be done securely)
        user = user_collection.find_one({"username": username})
        if user and check_password_hash(user['password'], password):
            token = generate_token(username)
            resp = make_response(redirect(url_for('profile')))
            resp.set_cookie('jwt', token)
            return resp
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

# Route to delete user's profile picture
@app.route('/delete/<id>', methods=['GET', 'POST'])
def delete(id):
    user = user_collection.find_one({"_id": ObjectId(id)})
    if user:
        picture = user.get('picture')
        if picture:
            file_path = os.path.join(app.config['UPLOADS'], picture)
            if os.path.exists(file_path):
                os.remove(file_path)
                update_user_picture(None, id)  # Remove picture from DB
                flash(f"Deleted file: {file_path}", 'success')
            else:
                flash("File not found", 'error')
        return redirect(url_for('profile'))
    else:
        flash("User not found.", 'error')
        return redirect(url_for('profile'))

# Route for accessing uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOADS'], filename)

# Route to register a new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        print(f"Attempting to register user: {username}")  # Debugging line

        # Check if the username already exists
        if user_collection.find_one({"username": username}):
            flash('Username already exists.', 'error')
            print(f"Username {username} already exists.")  # Debugging line
        else:
            user_collection.insert_one({"username": username, "password": password_hash})
            flash('User registered successfully.', 'success')
            print(f"User {username} registered successfully.")  # Debugging line
            return redirect(url_for('login'))
    
    return render_template('register.html')

# Route to get public list of users
@app.route('/users')
def users():
    all_users = user_collection.find()
    return render_template('users.html', users=all_users)

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)
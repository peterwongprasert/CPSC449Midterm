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
app.config['EXTENSIONS'] = ['.jpg', '.jpeg', '.pdf', '.png']
JWT_SECRET = os.getenv('JWT_SECRET', 'my_secret_jwt_key')
JWT_EXPIRATION = timedelta(hours=1)  # 1 hour

# Initialize PyMongo (assuming MongoDB is used)
# You should configure this with your MongoDB URI
app.config["MONGO_URI"] = os.getenv('MONGO_URI', "mongodb://localhost:27017/your_database")
mongo = PyMongo(app)
user_collection = mongo.db.users  # Adjust according to your MongoDB collection name

# Helper function to generate JWT token
def generate_token(username):
    payload = {
        "username": username,
        "exp": datetime.utcnow() + JWT_EXPIRATION
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

# Route for uploading files
@app.route('/sendFile', methods=['POST', 'GET'])
def sendFile():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = secure_filename(uploaded_file.filename)
            if os.path.splitext(filename)[1] in app.config['EXTENSIONS']:
                uploaded_file.save(os.path.join(app.config['UPLOADS'], filename))
                return 'File uploaded successfully'
            else:
                flash('Invalid file extension.', 'error')
        else:
            flash('No file selected.', 'error')
    return ''

# Update user's profile picture
def update_user_picture(filename, user_id):
    result = user_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"picture": filename}}
    )
    if result.matched_count > 0:
        return jsonify({"message": "User updated successfully"})
    else:
        return jsonify({"error": "User not found"}), 404

# Route for displaying profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    token = request.cookies.get('jwt')
    if not token:
        return redirect(url_for('login'))

    try:
        user_data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
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

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)
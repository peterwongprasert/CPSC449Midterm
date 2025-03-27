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
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
JWT_SECRET = os.getenv('JWT_SECRET', 'my_secret_jwt_key')
JWT_EXPIRATION = timedelta(hours=1)  # 1 hour

### BE SURE TO CHANGE ROUTING IF YOU ARE PULLING ====================================
# MOGO URI = YOUR DB NAME
# ===================================================================================

# Initialize PyMongo (assuming MongoDB is used)
# You should configure this with your MongoDB URI
app.config["MONGO_URI"] = os.getenv('MONGO_URI', "mongodb://localhost:27017/midterm")
mongo = PyMongo(app)
db = mongo.db
user_collection = db['midterm']

# Helper function to generate JWT token
def generate_token(username, id):
    payload = {
        "username": username,
        "id": id,
        "exp": datetime.utcnow() + JWT_EXPIRATION
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    
    return token

# Route for uploading files
@app.route('/sendFile/<id>', methods=['POST', 'GET'])
def sendFile(id):
    if request.method == 'POST':
        uploaded_file = request.files['file']

        uploaded_file.seek(0, os.SEEK_END)
        file_size = uploaded_file.tell()
        uploaded_file.seek(0)

        if file_size > app.config['MAX_CONTENT_LENGTH']:
            return jsonify({"error": "File size too large. Maximum size is 10 MB."}), 413
        
        if uploaded_file.filename != '':
            filename = secure_filename(uploaded_file.filename)
            user_filename = f"{id}-{filename}"
            if os.path.splitext(filename)[1] in app.config['EXTENSIONS']:

                delete_picture(id)

                uploaded_file.save(os.path.join(app.config['UPLOADS'], user_filename))
                update_user_picture(user_filename, id)


                return '''
                File uploaded successfully
                <a href='/profile'>Return to profile</a>
                '''
            else:
                flash('Invalid file extension.', 'error')
        else:
            flash('No file selected.', 'error')
    return ''

@app.route('/error')
def error_page():
    return render_template('error.html')


# Update user's profile picture
def update_user_picture(filename, user_id):
    result = user_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"picture": filename}}
    )
    return result.matched_count > 0

# Route for displaying profile
@app.route('/profile')
def profile():
    token = request.cookies.get('jwt')
    if not token:
        flash('You are not logged in.', 'error')
        return redirect(url_for('login'))

    try:
        user_data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = user_collection.find_one({"username": user_data['username']})
        if user:
            # If user has no profile picture, set a default one
            user['picture'] = user.get('picture', 'default.jpg')
            return render_template('profile.html', user=user)
        
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

        if request.form.get('sign-up') == 'True':
            hashed_pw = generate_password_hash(password)
            user_collection.insert_one({
                "user": username,
                "pw": hashed_pw
            })
        else:
            user = user_collection.find_one({"username": username})
            # if user and check_password_hash(user['pw'], password):
            if user and user['password'] == password:
                token = generate_token(username, str(user.get('_id')))
                resp = make_response(redirect(url_for('profile')))
                resp.set_cookie('jwt', token)
                return resp
            else:
                flash('Invalid username or password.', 'error')

    # Check if JWT token exists before decoding it
    token = request.cookies.get('jwt')
    
    if token:
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return redirect(url_for('profile'))
        except jwt.ExpiredSignatureError:
            flash('Session expired. Please log in again.', 'error')
        except jwt.InvalidTokenError:
            flash('Invalid token. Please log in again.', 'error')

    return render_template('login.html')


# Route to delete user's profile picture
@app.route('/delete/<id>', methods=['GET', 'POST'])
def delete_picture(id):
    token = request.cookies.get('jwt')
    
    if token:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Unauthorized user"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Unauthorized user"}), 401
        
        if not payload['id'] == id:
            flash("Unauthorized user.", "error")
            return redirect(url_for('error_page'))
    else:
        flash("No token provided. Unauthorized access.", "error")
        return redirect(url_for('error_page'))

    user = user_collection.find_one({"_id": ObjectId(id)})
    if user:
        picture = user.get('picture')
        if picture and picture != "default.jpg":
            file_path = os.path.join(app.config['UPLOADS'], picture)
            if os.path.exists(file_path):
                os.remove(file_path)
                flash(f"Deleted file: {file_path}", 'success')
                
                user_collection.update_one(
                {"_id": ObjectId(id)},
                {"$unset": {"picture": ""}}
            )
            else:
                flash("File not found", 'error')
        return redirect(url_for('profile'))
    else:
        flash("User not found.", 'error')
        return redirect(url_for('profile'))
    
# delete the user profile
@app.route('/delete_user/<id>', methods=['GET', 'POST'])
def delete_user(id):
    token = request.cookies.get('jwt')
    
    if token:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Unauthorized user"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Unauthorized user"}), 401
        
        if not payload['id'] == id:
            flash("Unauthorized user.", "error")
            return redirect(url_for('error_page'))
    else:
        flash("No token provided. Unauthorized access.", "error")
        return redirect(url_for('error_page'))

    delete_picture(id)

    result = user_collection.delete_one({"_id": ObjectId(id)})

    if not result.deleted_count == 1:
        return jsonify({"error": "User not found"}), 400
        
    return redirect(url_for('logout'))

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
        # password_hash = generate_password_hash(password, method='pbkdf2:sha256')

        if user_collection.find_one({"username": username}):
            flash('Username already exists.', 'error')
        else:
            user_collection.insert_one({"username": username, "password": password, "picture": "default.jpg"})
            flash('User registered successfully.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/users', methods=['GET'])
def users():
    all_users = user_collection.find()
    count = user_collection.count_documents({})
    return render_template('users.html', users=all_users, count=count)

#used for DB testing purposes only
@app.route('/getAllUsers', methods=['GET', 'POST'])
def getAllUsers():
    #we need to convert MongoDB collections into Python Dictionary
    users = list(user_collection.find())

    if request.method == "POST":
        username = request.form['username']
        pw = request.form['password']

        if username == None or pw == None:
            return 
        
        user_collection.insert_one({
                "user" : username,
                "pw" : pw
            })

    for user in users:
        user['_id'] = str(user['_id'])
    return jsonify(users)

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)

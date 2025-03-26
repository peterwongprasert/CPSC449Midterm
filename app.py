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

### BE SURE TO CHANGE ROUTING IF YOU ARE PULLING ====================================
# MOGO URI = YOUR DB NAME
# user <--> username
# pw <--> password
# ===================================================================================

# Initialize PyMongo (assuming MongoDB is used)
# You should configure this with your MongoDB URI
app.config["MONGO_URI"] = os.getenv('MONGO_URI', "mongodb://localhost:27017/midterm")
mongo = PyMongo(app)
db = mongo.db
user_collection = db['midterm']

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
    delete_picture(id)
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = secure_filename(uploaded_file.filename)
            user_filename = f"{id}-{filename}"
            if os.path.splitext(filename)[1] in app.config['EXTENSIONS']:
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
        user = user_collection.find_one({"user": user_data['username']})
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
        
        if request.form.get('sign-up') == 'True':
            user_collection.insert_one({
                "user" : username,
                "pw" : password
            })
        else:
        # Validate login credentials (this should be done securely)
            user = user_collection.find_one({"user": username})
            if user and check_password_hash(user['pw'], password):
                token = generate_token(username)
                resp = make_response(redirect(url_for('profile')))
                resp.set_cookie('jwt', token)
                return resp
            else:
                flash('Invalid username or password.', 'error')

    #if valid token redirect to profile
    token = jwt.decode(request.cookies.get('jwt'), JWT_SECRET, algorithms=["HS256"])
    if token:
        return redirect(url_for('profile'))
    
    return render_template('login.html')

# Route to delete user's profile picture
@app.route('/delete/<id>', methods=['GET', 'POST'])
def delete_picture(id):
    user = user_collection.find_one({"_id": ObjectId(id)})
    if user:
        picture = user.get('picture')
        if picture:
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

@app.route('/deleteUser/<id>', methods=['POST'])
def delete_user(id):

    delete_picture(id)

    result = user_collection.delete_one({"_id": ObjectId(id)})

    if not result.deleted_count == 1:
        return jsonify({"error": "User not found"}), 400
        
    return redirect(url_for('logout'))

# Route for accessing uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOADS'], filename)

#used for DB testing purposes only
@app.route('/users', methods=['GET', 'POST'])
def users():
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

### TODO: Add max size capacity, delete images once we update user picture, add user count in login screen
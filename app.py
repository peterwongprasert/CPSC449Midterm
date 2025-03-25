from flask import Flask, render_template, request, redirect, url_for, make_response, session, flash, jsonify, send_from_directory
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import jwt
import datetime
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/midterm"
mongo = PyMongo(app)
db = mongo.db
user_collection = db['midterm']
items_collection = db['items']

JWT_SECRET = 'my_secret_jwt_key'
JWT_EXPIRATION = 1  # 1 HR

app.secret_key = 'super_secret'
app.config['extensions'] = ['.jpg', '.jpeg', '.pdf', '.png']
app.config['UPLOADS'] = 'uploads'
app.config['SECRET_KEY'] = 'super_secret'
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

if not os.path.exists(app.config['UPLOADS']):
    os.makedirs(app.config['UPLOADS'])

def generate_token(username):
    """Generates a JWT token for authentication"""
    payload = {
        "username": username,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=JWT_EXPIRATION)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token

def decode_token(token):
    """Decodes a JWT token and handles expiration or invalid token errors"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def update_user_picture(filename, id):
    """Updates user profile picture in the database"""
    result = user_collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": {"picture": filename}}
    )
    return result.matched_count > 0

def allowed_file_size(file):
    """Checks if the uploaded file size is within the allowed limit"""
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    return size <= MAX_FILE_SIZE

# Error Handlers
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad Request", "message": "Invalid input"}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found", "message": "Resource not found"}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Internal Server Error", "message": "Something went wrong"}), 500

# Authentication and User Login
@app.route('/', methods=['GET', 'POST'])
def login():
    token = request.cookies.get('jwt')
    user_count = user_collection.count_documents({})
    
    if request.method == 'POST':
        username = request.form['username']
        pw = request.form['password']
        
        if not username or not pw:
            flash("No input found", "error")
            return redirect(url_for('login'))
        
        if request.form.get('sign-up') == 'True':
            user_collection.insert_one({"user": username, "pw": pw})
        else:
            user = user_collection.find_one({"user": username})
            if user and user['pw'] == pw:
                token = generate_token(username)
                resp = make_response(redirect(url_for('profile')))
                resp.set_cookie('jwt', token)
                return resp
            else:
                flash("Invalid username/password", "error")
                return redirect(url_for('login'))
    
    if token:
        payload = decode_token(token)
        if payload:
            return redirect(url_for('profile'))
    
    return render_template('login.html', user_count=user_count)

# File Upload Handling
@app.route('/sendFile/<id>', methods=['POST'])
def sendFile(id):
    """Handles file uploads with validation for size and type"""
    uploaded_file = request.files['file']
    if uploaded_file.filename:
        filename = secure_filename(uploaded_file.filename)
        file_extension = os.path.splitext(filename)[1]

        if file_extension not in app.config['extensions']:
            flash("Invalid file format", "error")
            return redirect(url_for('profile'))
        
        if not allowed_file_size(uploaded_file):
            flash("File size exceeds the 2MB limit", "error")
            return redirect(url_for('profile'))
        
        uploaded_file.save(os.path.join(app.config['UPLOADS'], filename))
        update_user_picture(filename, id)
        return redirect(url_for('profile'))
    
    flash("No file uploaded", "error")
    return redirect(url_for('profile'))

# Public Route
@app.route('/public-info', methods=['GET'])
def public_info():
    """Returns public information that does not require authentication"""
    data = [
        {"title": "Welcome", "description": "This is a public API endpoint"},
        {"title": "API Status", "description": "Up and running"}
    ]
    return jsonify(data), 200

# CRUD Operations for Items
@app.route('/items', methods=['GET'])
def get_items():
    """Retrieves all items from the database"""
    items = list(items_collection.find({}, {"_id": 0}))
    return jsonify(items), 200

@app.route('/items', methods=['POST'])
def create_item():
    """Creates a new item"""
    data = request.json
    if not data or "name" not in data:
        return jsonify({"error": "Invalid input"}), 400
    
    item = {"name": data["name"], "description": data.get("description", "")}
    items_collection.insert_one(item)
    return jsonify({"message": "Item added"}), 201

@app.route('/items/<string:name>', methods=['PUT'])
def update_item(name):
    """Updates an existing item"""
    data = request.json
    result = items_collection.update_one({"name": name}, {"$set": data})
    
    if result.matched_count == 0:
        return jsonify({"error": "Item not found"}), 404
    
    return jsonify({"message": "Item updated"}), 200

@app.route('/items/<string:name>', methods=['DELETE'])
def delete_item(name):
    """Deletes an item from the database"""
    result = items_collection.delete_one({"name": name})
    
    if result.deleted_count == 0:
        return jsonify({"error": "Item not found"}), 404
    
    return jsonify({"message": "Item deleted"}), 200

if __name__ == '__main__':
    app.run(debug=True)
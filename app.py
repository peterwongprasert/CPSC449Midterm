from flask import Flask, render_template, request, redirect, url_for, make_response, session, flash, jsonify, send_from_directory
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import jwt
import datetime
import os
from werkzeug.utils import secure_filename

app= Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/midterm"
mongo = PyMongo(app)
db = mongo.db
user_collection = db['midterm']

JWT_SECRET = 'my_secret_jwt_key'
JWT_EXPIRATION = 1 #1 HR

# file upload code
app.secret_key = 'super_secret'
app.config['extentions'] = ['.jpg', '.jpeg', '.pdf', '.png']
app.config['UPLOADS'] = 'uploads'
app.config['SECRET_KEY'] = 'super_secret'

def generate_token(username):
    payload = {
        "username" : username,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=JWT_EXPIRATION)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token

def decode_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        flash("Session exipired. Please log in again", "error")
        return None
    except jwt.InvalidTokenError:
        flash("Invalid token. Please log in again", "error")


def update_user_picture(filename, id):
    obj = {}
    obj['picture'] = filename

    result = user_collection.update_one(
        {"_id": ObjectId(id)},
        {"$set": obj}
    )

    if result.matched_count > 0:
        return jsonify({"message": "User updated successfully"})
    else:
        return jsonify({"error": "User not found"}), 404
    
@app.route('/', methods=['GET', 'POST'])
def login():
    token = request.cookies.get('jwt')
    if request.method == 'POST':
        username = request.form['username']
        pw = request.form['password']

        if not (username or pw):
            flash("No input found", "error")
            return redirect(url_for('login'))
        
        #user is signing up
        if request.form.get('sign-up') == 'True':
            user_collection.insert_one({
                "user" : username,
                "pw" : pw
            })
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

    #if valid token redirect to profile
    if token:
        payload = decode_token(token)
        if payload:
            return redirect(url_for('profile'))

    return render_template('login.html')

@app.route('/sendFile/<id>',methods=['POST','GET'])
def sendFile(id):
    delete_picture(id)
    uploaded_file = request.files['file']
    if uploaded_file.filename != '':
        filename = secure_filename(uploaded_file.filename)
        if os.path.splitext(filename)[1] in app.config['extentions']:
            uploaded_file.save(os.path.join(app.config['UPLOADS'],filename))
            # return 'correct'
            update_user_picture(filename, id)
            return redirect(url_for('profile'))
    return ''

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOADS'], filename)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    token = request.cookies.get('jwt')

    if not token:
        flash(token, "error")
        return redirect(url_for('login'))
    
    payload = decode_token(token)
    if not payload:
        flash('Invalid token')
        return redirect(url_for('login'))
    
    #valid user login proceeding to fetch user and display info
    username = payload['username']
    user = user_collection.find_one({"user": username})

    return render_template('profile.html', user=user)

@app.route('/delete/<id>', methods=['GET', 'POST'])
def delete_picture(id):
    user = user_collection.find_one({"_id": ObjectId(id)})

    if user:
        picture = user.get('picture')

        if picture:
            file_path = os.path.join(app.config['UPLOADS'], picture)

            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted file: {file_path}")
            else:
                print("File not found")

    return redirect(url_for('profile'))

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('jwt')
    return resp

if __name__ == '__main__':
    app.run(debug=True)
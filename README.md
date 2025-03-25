# Flask User Management API

## Project Overview
This project is a Flask-based RESTful API that implements user authentication, file handling, error handling, and public/admin routes. The API allows users to register, authenticate using JWT, upload files with validation, and perform CRUD operations on items.

## Team Members
1. Peter Wong
2. Ian Gabriel Vista

## Prerequisites
Ensure you have the following installed:
- Python 3.x
- MongoDB (for database storage)
- Flask and required dependencies

## Setup Instructions

### Step 1: Clone the Repository
```bash
git clone <repository-url>
cd <repository-folder>
```

### Step 2: Create a Virtual Environment (Optional but Recommended)
```bash
python -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate  # On Windows
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure the Database
1. Start MongoDB service.
2. Ensure the database URI is set correctly in `app.config["MONGO_URI"]` in `app.py`.

### Step 5: Run the Application
```bash
python app.py
```
The application will run on `http://127.0.0.1:5000/` by default.

## API Endpoints

### Authentication
- `POST /login` - Logs in the user and returns a JWT token.
- `POST /register` - Registers a new user.

### Public Routes
- `GET /public-info` - Returns public data without authentication.

### Protected Routes (Require Authentication)
- `POST /sendFile/<id>` - Uploads a file with validation.
- `GET /items` - Retrieves all items.
- `POST /items` - Adds a new item.
- `PUT /items/<name>` - Updates an existing item.
- `DELETE /items/<name>` - Deletes an item.

### Error Handling
- Returns appropriate JSON responses for errors like 400 (Bad Request), 401 (Unauthorized), 404 (Not Found), and 500 (Internal Server Error).

## Running in Development Mode
Use the debug mode for development:
```bash
export FLASK_ENV=development
flask run
```

## Testing with Postman
1. Import the provided Postman collection.
2. Authenticate using the `/login` endpoint and include the token in protected routes.
3. Test all endpoints.

## Submission Requirements
- Ensure all required files (code, `requirements.txt`, `README.md`, Postman screenshot, and demo video) are included.

---

For any issues, refer to the project documentation or contact a team member.
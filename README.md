# Flask User Management API

## Project Overview
This project is a **Flask-based RESTful API** that implements user authentication, file handling, error handling, and various routes for both public and admin users. The API enables users to register, authenticate using JWT, upload files with validation, and perform CRUD operations on items such as profiles and pictures.

### Key Features:
- **User Authentication**: JWT-based login and token validation.
- **User Registration**: Secure sign-up with password hashing.
- **File Upload**: Users can upload, view, and delete their profile pictures.
- **Public Routes**: Users can access public information.
- **Admin Routes**: Administrators can manage user data and perform CRUD operations on items.
- **Error Handling**: Proper error messages and status codes for common issues (e.g., 400, 401, 404).

## Team Members
1. **Peter Wongprasert**
2. **Ian Gabriel Vista**

## Prerequisites
Ensure you have the following installed:
- **Python 3.x**: The programming language used to implement this API.
- **MongoDB**: A NoSQL database for storing user information and other data.
- **Flask**: A lightweight WSGI web application framework.
- **Flask-PyMongo**: Flask extension to interact with MongoDB.

#### Dependencies
Flask==3.1.0                         
Flask-PyMongo==3.0.1                 
pymongo==4.11.3                      
PyJWT==2.9.0                         
Werkzeug==3.1.3                      

## Setup Instructions

### Step 1: Clone the Repository
Clone this repository to your local machine:

```bash
  git clone <repository-url>
```
### Step 2: Serve MongoDB
How to run locally:
``` Powershell
  cd "Path\to\mongod.exe"
  .\mongod --dbpath "Path\to\MongoDB\data"
```
*Note: If you do not have a data folder for MongoDB, you must manually create it.

### Step 3: Run app.py
```bash
  python app.py
```

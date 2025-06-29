from flask import current_app as app, jsonify,request # this is used to access the current application context which was defined in app.py
#this also prevents circular imports
from application.database import db  # import the database instance from the database module
from flask_security import auth_required, roles_required, current_user,hash_password  # import the decorators and current user from Flask-Security

@app.route("/api/admin")
@auth_required('token')  # this decorator ensures that the user is authenticated before accessing the route
@roles_required('admin')  # this decorator ensures that the user has the 'admin'

#@roles_required('admin','user')  # user and admin
#@roles_accepted('admin','user')  # user or admin
def admin_home():
    return '<h1>Welcome to the Admin Home Page!</h1>'
# This route is for the admin home page, only accessible to users with the 'admin' role



@app.route("/api/home")
@auth_required('token')  # this decorator ensures that the user is authenticated before accessing the
def user_home():
    
    return jsonify({
        "username": current_user.username,
        "email": current_user.email,
        "roles": [role.name for role in current_user.roles],
        "password": current_user.password  # this is not recommended to return password in response, but for demonstration purposes
    }), 200  # return the user details in JSON format with a 200 OK status
# This route is for the user home page, accessible to all authenticated users


@app.route("/api/register", methods=['POST'])
def register():
    # This route is for user registration, you can implement the registration logic here
    credentials = request.get_json()
    if not credentials or not credentials.get('username') or not credentials.get('email') or not credentials.get('password'):
        return jsonify({"error": "Missing required fields"}), 400
    # Here we would typically save the user to the database
    username = credentials['username']
    email = credentials['email']
    password = credentials['password']
    if app.security.datastore.find_user(username=username):
        return jsonify({"error": "Username already exists,please try with different username"}), 400
    elif not app.security.datastore.find_user(email=email ):
        user = app.security.datastore.create_user(
            email = email,
            username = username,
            password = hash_password(password),  # hash the password using the configured hashing algorithm
            roles = ['user']  # assign roles to the user, can't add roles that do not exist
        )
        db.session.commit()
    else:
        return jsonify({"error": "Email already exists"}), 400
    
    return jsonify({"message": "User registered successfully"}) ,201
# This route is for user registration, it accepts a JSON payload with 'username', 'email






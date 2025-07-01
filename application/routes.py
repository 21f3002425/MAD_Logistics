from flask import current_app as app, jsonify,request # this is used to access the current application context which was defined in app.py
#this also prevents circular imports
from application.database import db  # import the database instance from the database module
from flask_security import auth_required, roles_required, current_user,login_user  # import the decorators and current user from Flask-Security
from application.models import User, Role, Transactions  # import the models from the models module
from werkzeug.security import generate_password_hash, check_password_hash  # import the password hashing functions from Werkzeug

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
@app.route("/api/login", methods=['POST'])
def user_login():
    data = request.get_json()
    if current_user.is_authenticated:
        return jsonify({"message": "User already logged in", "username": current_user.username, "user_id": current_user.id}), 400
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Missing required fields"}), 400
    username = data['username']
    password = data['password']
    user = app.security.datastore.find_user(username=username)
    if user and check_password_hash(user.password, password):
        login_user(user)  # Log the user in using Flask-Security's login_user function
        # Generate a token for the user
        
        return jsonify({"auth_token": user.get_auth_token(), "message": "Login successful","username":user.username,"user_id": user.id}), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401  
      


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
            password = generate_password_hash(password),  # hash the password using the configured hashing algorithm
            roles = ['user']  # assign roles to the user, can't add roles that do not exist
        )
        db.session.commit()
    else:
        return jsonify({"error": "Email already exists"}), 400
    
    return jsonify({"message": "User registered successfully"}) ,201
# This route is for user registration, it accepts a JSON payload with 'username', 'email


@app.route("/api/pay/<int:transaction_id>")
@auth_required('token')  # this decorator ensures that the user is authenticated before accessing the route
@roles_required('user')  # this decorator ensures that the user has the 'user' role
def payment(transaction_id):
    transaction = Transactions.query.get(transaction_id)
    if not transaction:
        return jsonify({"error": "Transaction not found"}), 404
    transaction.internal_status = 'paid'
    db.session.commit()
    return jsonify({"message": "Transaction paid successfully"}), 200


# This route is for processing payments, it updates the internal status of the transaction to 'paid'
@app.route("/api/update_delivery_status/<int:transaction_id>", methods=['PUT'])
@auth_required('token')  # this decorator ensures that the user is authenticated before accessing the route
@roles_required('admin')  # this decorator ensures that the user has the 'admin'
def update_delivery_status(transaction_id):
    transaction = Transactions.query.get(transaction_id)
    if not transaction:
        return jsonify({"error": "Transaction not found"}), 404
    data = request.get_json()
    if not data or 'delivery_status' not in data:
        return jsonify({"error": "Missing delivery status"}), 400
    transaction.delivery_status = data['delivery_status']
    db.session.commit()
    return jsonify({"message": f"Delivery status updated successfully to '{transaction.delivery_status}'"}), 200
# This route is for updating the delivery status of a transaction, it accepts a JSON payload with 'delivery_status'



@app.route("/api/update_amount/<int:transaction_id>", methods=['POST']) #admin can update amount and internal status will be "Payment Pending"
@auth_required('token')  # this decorator ensures that the user is authenticated before accessing the
@roles_required('admin')  # this decorator ensures that the user has the 'admin'
def update_transaction_details(transaction_id):
    transaction = Transactions.query.get(transaction_id)
    if not transaction:
        return jsonify({"error": "Transaction not found"}), 404
    transaction.amount = request.json.get('amount', transaction.amount)
    transaction.internal_status = "Payment Pending"
    amount = transaction.amount
    db.session.commit()
    return jsonify({"message": "details updated successfully",
                    "id": transaction_id,
                    "amount": str(amount),
                    "internal_status":transaction.internal_status}), 200
# This route is for updating the transaction details, it accepts a JSON payload with 'amount' and 'delivery_date'
# and updates the transaction in the database. The internal status is set to "Payment Pending"



@app.route("/api/update_delivery_date/<int:transaction_id>", methods=['POST']) #admin can update delivery date after payment is done
@auth_required('token')  # this decorator ensures that the user is authenticated before accessing the
@roles_required('admin')  # this decorator ensures that the user has the 'admin'
def update_delivery_date(transaction_id):
    transaction = Transactions.query.get(transaction_id)
    if not transaction:
        return jsonify({"error": "Transaction not found"}), 404
    transaction.delivery = request.json.get('delivery_date', transaction.delivery)
    delivery_date = transaction.delivery
    db.session.commit()
    return jsonify({"message": "Delivery date updated successfully",
                    "transaction_id": transaction_id,
                    "delivery_date": str(delivery_date),
                    "user" : transaction.bearer.username,
                    "user_id":transaction.bearer.id}), 200

@app.route("/api/review_transaction/<int:transaction_id>", methods=['GET']) #admin can review transaction
@auth_required('token')  # this decorator ensures that the user is authenticated before accessing the
@roles_required('admin','user')  # this decorator ensures that the user has the 'admin'
def review_transaction(transaction_id):
    transaction = Transactions.query.get(transaction_id)
    if not transaction:
        return jsonify({"error": "Transaction not found"}), 404
    if current_user.id != transaction.user_id and not current_user.has_role('admin'):
        return jsonify({"error": "You do not have permission to view this transaction"}), 403
    transaction_details = {
        "id": transaction.id,
        "name": transaction.name,
        "user_id": transaction.user_id,  # current_user.id
        "type": transaction.type,
        "initiation_date": transaction.date,
        "delivery_date": transaction.delivery,
        "source_city": transaction.source_city,
        "destination_city": transaction.destination_city,
        "internal_status": transaction.internal_status,
        "delivery_status": transaction.delivery_status,
        "description": transaction.description,
        "amount": transaction.amount,
        "user": transaction.bearer.username,  # get the username of the user who created the transaction
        "user_id": transaction.bearer.id  # get the user id of the user
    }
    return jsonify(transaction_details), 200  # return the transaction details in JSON format with a

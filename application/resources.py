from flask_restful import Resource, Api, reqparse
from flask import jsonify, request

#We will use Flask-RESTful to create RESTful APIs for our application
from .database import db  # import the database instance from the database module
from .models import User, Role, Transactions, City  # import the models from the models module
from flask_security import auth_required, roles_required, current_user, hash_password, roles_accepted  # import the
# decorators and current user from Flask-Security

api = Api()  # create an instance of Flask-RESTful API

parser = reqparse.RequestParser()  # create a request parser to handle incoming requests
parser.add_argument('name', type=str, required=True, help='Name of the transaction is required')
parser.add_argument('type', type=str, required=True, help='Type of the transaction is required')
parser.add_argument('date', type=str, required=True, help='Date of the transaction is required')
parser.add_argument('source_city', type=str, required=True, help='Source city of the transaction is required')
parser.add_argument('destination_city', type=str, required=True, help='Destination city of the transaction is required')
parser.add_argument('description', type=str, required=False, help='Description of the transaction is optional')


def role_list(roles):
        return [role.name for role in roles]

class TransApi(Resource):
    @auth_required('token')  # this decorator ensures that the user is authenticated before accessing the route
    @roles_accepted('admin', 'user')  # this decorator ensures that the user has the 'admin' or 'user' role
    def get(self):
        transactions=[] #will store transaction objects
        trans_json = [] #will store transaction json objects(dictonaries)
        if "admin" in role_list(current_user.roles):
            transactions = Transactions.query.all()
        else:
            transactions = current_user.transacions
        
        #lets convert the transactions to json format
        for transaction in transactions:
            this_transaction = {}
            this_transaction['id'] = transaction.id
            this_transaction['name'] = transaction.name
            this_transaction['user_id'] = transaction.user_id #/current_user.id
            this_transaction['type'] = transaction.type
            this_transaction['date'] = transaction.date
            this_transaction['delivery_date'] = transaction.delivery
            this_transaction['source_city'] = transaction.source_city
            this_transaction['destination_city'] = transaction.destination_city
            this_transaction['internal_status'] = transaction.internal_status
            this_transaction['delivery_status'] = transaction.delivery_status
            this_transaction['description'] = transaction.description
            this_transaction['amount'] = transaction.amount
            this_transaction['user'] = transaction.bearer.username  # get the username of the user who created the transaction
            trans_json.append(this_transaction)
        if trans_json:
            return trans_json, 200  # return the transaction details in JSON format with a 200 OK status
        else:
            return {"message": "No transactions found"}, 404
    
    @auth_required('token')  # this decorator ensures that the user is authenticated before accessing the route
    @roles_accepted('admin', 'user')  # this decorator ensures that the user has the 'admin' or 'user' role
    def post(self):
        args = parser.parse_args() #retreave the arguments from the request body
        try:
            transaction = Transactions(
                name=args['name'],
                type=args['type'],
                date=args['date'],
                source_city=args['source_city'],
                destination_city=args['destination_city'],
                description=args.get('description', None),
                user_id=current_user.id,  # set the user_id to the current user's id
                internal_status="requested",  # default status
            )
        except Exception as e:
            return {"message": "One or more of required fields are missing"}, 400
        db.session.add(transaction)  # add the transaction to the session
        db.session.commit()  # commit the session to save the transaction to the database
        return {"message": "Transaction created successfully", "transaction_id": transaction.id}, 200
    
    
    
    @auth_required('token')  # this decorator ensures that the user is authenticated before accessing the route
    @roles_accepted('admin', 'user')  # this decorator ensures that the user has the 'admin' or 'user' role
    def put(self,transaction_id):
        args = parser.parse_args()
        transaction = Transactions.query.get(transaction_id)
        if not transaction:
            return {"message": "Transaction not found"}, 404
        transaction.name = args.get('name', transaction.name)  # update the name if provided, else keep the existing name
        transaction.type = args.get('type', transaction.type)  # update the type if provided, else keep the existing type
        transaction.date = args.get('date', transaction.date)  # update the date if provided, else keep the existing date
        transaction.source_city = args.get('source_city', transaction.source_city)  # update the source city if provided, else keep the existing source city
        transaction.destination_city = args.get('destination_city', transaction.destination_city)  # update the destination city if provided, else keep the existing destination city
        transaction.description = args.get('description', None)
        db.session.commit()  # commit the session to save the changes to the database
        return {"message": "Transaction updated successfully"}, 200
    



    @auth_required('token')  # this decorator ensures that the user is authenticated before accessing the route
    @roles_accepted('admin', 'user')  # this decorator ensures that the user
    def delete(self, transaction_id):
        transaction = Transactions.query.get(transaction_id)
        if not transaction:
            return {"message": "Transaction not found"}, 404
        db.session.delete(transaction)  # delete the transaction from the session
        db.session.commit()  # commit the session to save the changes to the database
        return {"message": "Transaction deleted successfully"}, 200

api.add_resource(TransApi, '/api/get',
                 '/api/create',
                 '/api/update/<int:transaction_id>',
                 '/api/delete/<int:transaction_id>')  # add the TransApi resource to the API with the specified endpoint
        
    









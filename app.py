from flask import Flask
from application.database import db
from application.models import User, Role
from application.config import LocalDevelopmentConfig
from flask_security import Security, datastore, SQLAlchemyUserDatastore, hash_password
from application.resources import api  # import the API instance from the resources module
from werkzeug.security import generate_password_hash, check_password_hash  # import the password hashing functions from Werkzeug


def create_app():
    app = Flask(__name__)
    app.config.from_object(LocalDevelopmentConfig)
    db.init_app(app)
    api.init_app(app)  # initialize the Flask-RESTful API with the Flask app
    datastore = SQLAlchemyUserDatastore(db, User, Role) # datastore is used by Flask-Security to manage users and roles, to prefill the database with initial data
    app.security = Security(app, datastore)
    app.app_context().push()
    return app

app = create_app()

with app.app_context(): # all the crud operations and database initializations should be done within an application context
    db.create_all()  # create the database tables, this will only create tables if they do not exist
    app.security.datastore.find_or_create_role(name = 'admin', description='Super user of app')  # create an admin role if it does not exist
    app.security.datastore.find_or_create_role(name = 'user', description='Normal user of app')  # create a user role if it does not exist
    db.session.commit()  # commit the changes to the database, this is needed because roles should be there in the database before creating users

    if not app.security.datastore.find_user(email='user0@admin.com'):
        user = app.security.datastore.create_user(
            email = 'user0@admin.com',
            username = 'admin01',
            password = generate_password_hash('1234'),  # hash the password using the configured hashing algorithm
            roles = ['admin','user'] # assign roles to the user, can't add roles that do not exist  

        )
    if not app.security.datastore.find_user(email='user01@user.com'):
        user = app.security.datastore.create_user(
            email = 'user01@user.com',
            username = 'user01',
            password = generate_password_hash('1234'),  # hash the password using the configured hashing algorithm
            roles = ['user']  # assign roles to the user, can't add roles that do not exist

        )
    db.session.commit()  # commit the changes to the database

from application.routes import *  # import all the routes from the routes module



if __name__ == "__main__":
    app.run()


#now we will use postman to test the application
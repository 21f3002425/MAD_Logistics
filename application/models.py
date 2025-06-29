from .database import db
from flask_security import UserMixin, RoleMixin

class User(db.Model, UserMixin):
    #required for flask security
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False) #fs_uniquifier somehow stores your username and email and generates a unique token for each user
    active = db.Column(db.Boolean(), default=True, nullable=False)
    roles = db.relationship('Role', backref='bearer', secondary='users_roles')  # many-to-many relationship with Role
    transacions = db.relationship('Transactions', backref='bearer')  # one-to-many relationship with Transactions
    #extra


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)

#many-to-many relationship between User and Role
class UsersRoles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

#transaction table
class Transactions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # e.g., 'edible','fragile','non-fragile'
    date = db.Column(db.String, nullable=False)
    delivery = db.Column(db.String, nullable=False, default= "to be updated")  
    source_city= db.Column(db.String(80), nullable=False)  # e.g., 'New York'
    destination_city= db.Column(db.String(80), nullable=False)  # e.g., 'Los Angeles')
    internal_status = db.Column(db.String(50), nullable=False, default="requested")  # e.g., 'pending', 'in transit', 'delivered'
    delivery_status = db.Column(db.String(50), nullable=False, default="processing")  # e.g., 'pending', 'delivered', 'cancel
    description = db.Column(db.String(255), nullable=True)  # additional details about the transaction
    amount = db.Column(db.Float, nullable=False, default = 1000)  # amount of the transaction, e.g., cost of delivery
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # foreign key to User table



# City model to represent cities in the database
class City(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

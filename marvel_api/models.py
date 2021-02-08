from marvel_api import app, db, login_manager, ma
import uuid         # this is the universal unique ids that it creates for us
from datetime import datetime

# adding Flask Security for Passwords
from werkzeug.security import generate_password_hash, check_password_hash

# Import for Secrets Module (Given by Python)
import secrets

# Imports for Login Manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):
    id = db.Column(db.String, primary_key = True )
    first_name = db.Column(db.String(150), nullable = True, default = '')
    last_name = db.Column(db.String(150), nullable = True, default = '')
    email = db.Column(db.String(150), nullable = False)
    password = db.Column(db.String, nullable = True, default = '')
    g_auth_verify = db.Column(db.Boolean, default = False)
    token = db.Column(db.String, default = '', unique = True)                         #used for api token, to give to user for specific amount of time, needs a unique flag
    data_created = db.Column(db.DateTime, nullable = False, default = datetime.utcnow)
    marvel = db.relationship('Marvel', backref = 'owner', lazy = True)

    def __init__(self, email,first_name = '', last_name = '', id = '', password = '', token = '', g_auth_verify = False):
        self.id = self.set_id()
        self.first_name = first_name
        self.last_name = last_name
        self.password = self.set_password(password)
        self.email = email
        self.token = self.set_token(24)
        self.g_auth_verify = g_auth_verify

    def set_token(self,length):
        return secrets.token_hex(length)
    
    def set_id(self):
        return str(uuid.uuid4())

    def set_password(self,password):
        self.pw_hash = generate_password_hash(password)
        return self.pw_hash
    
    def __repr__(self):
        return f'User {self.email} has been added to the database'

class Marvel(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(150))
    description = db.Column(db.String(250))
    comics_appeared_in = db.Column(db.Integer)
    super_power = db.Column(db.String(200))
    date_created = db.Column(db.DateTime, nullable = False, default = datetime.utcnow)
    user_id = db.Column(db.String, db.ForeignKey('user.token'), nullable = False)

    def __init__(self, name, description, comics_appeared_in, super_power, user_id):
        self.name = name
        self.description = description
        self.comics_appeared_in = comics_appeared_in
        self.super_power = super_power
        self.user_id = user_id

    def __repr__(self):
        return f'The following Marvel character has been added: {self.name} which belongs to {self.user_id}'
    
    def to_dict(self):
        return {
            "id":self.id,
            "name": self.name,
            "description":self.description,
            "comics_appeared_in":self.comics_appeared_in,
            "super_power": self.super_power
        }

# Creation of API Schema via the Marshmallow Object
class MarvelSchema(ma.Schema):
    class Meta:
        fields = ['id', 'name', 'description', 'comics_appeared_in', 'super_power']

marvel_schema = MarvelSchema()
marvels_schema = MarvelSchema(many = True)
from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    age = db.Column(db.Integer)
    sex = db.Column(db.String(150))
    phno = db.Column(db.Integer)
    first_name = db.Column(db.String(150))
    password = db.Column(db.String(150))



class Doctor(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    doc_id = db.Column(db.Integer, unique=True)
    domain = db.Column(db.String(150))
    phno = db.Column(db.Integer)
    first_name = db.Column(db.String(150))
    password = db.Column(db.String(150)) 
    varified = db.Column(db.Boolean, default=False)



class PatientComments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150))
    comments = db.Column(db.String(250))
    domain = db.Column(db.String(50))
    checked = db.Column(db.Boolean, default=False)




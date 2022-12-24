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

def __init__(self,email,age,sex,phno,first_name,password):
    self.email = email
    self.age = age
    self.sex = sex
    self.phno = phno
    self.first_name = first_name
    self.password = password



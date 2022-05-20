##############################  imports  ########################################

from flask import Flask, g, abort, request, make_response
from functools import wraps
import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime as dt, timedelta
import secrets

#################### init ############################
class Config():
    SQLALCHEMY_DATABASE_URI=os.environ.get("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_TRACK_MODIFICATIONS=os.environ.get("SQLALCHEMY_TRACK_MODIFICATIONS")

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()

@basic_auth.verify_password
def verify_password(email, password):
    #check to see if the user even exists
    u = User.query.filter_by(email=email).first()
    if u is None:
        return False
    g.current_user = u
    return u.check_hashed_password(password)

@token_auth.verify_token
def verify_token(token):
    u = User.check_token(token) if token else None
    g.current_user = u
    return u



def require_admin(f, *args, **kwargs):
    @wraps(f)
    def check_admin(*args, **kwargs):
        if not g.current_user.is_admin:
            abort(403)
        else:
            return f(*args, **kwargs)
    return check_admin


####################   User and Book Classes/ MOdels  ################################

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email =  db.Column(db.String, unique=True, index=True)
    password =  db.Column(db.String)
    is_admin = db.Column(db.Boolean, default=False)
    token = db.Column(db.String, index=True, unique=True)
    token_exp = db.Column(db.DateTime)

    def get_token(self, exp=86400):
        current_time = dt.utcnow()
        # give the user their back token if their is still valid
        if self.token and self.token_exp > current_time + timedelta(seconds=60):
            return self.token
        # if the token DNE or is exp
        self.token = secrets.token_urlsafe(32)
        self.token_exp = current_time + timedelta(seconds=exp)
        self.save()
        return self.token

    def revoke_token(self):
        self.token_exp = dt.utcnow() - timedelta(seconds=61)
    
    @staticmethod
    def check_token(token):
        u  = User.query.filter_by(token=token).first()
        if not u or u.token_exp < dt.utcnow():
            return None
        return u

    def hash_password(self, original_password):
        return generate_password_hash(original_password)

    # compares the user password to the password provided in the login form
    def check_hashed_password(self, login_password):
        return check_password_hash(self.password, login_password)

    def save(self):
        db.session.add(self) #adds the user to the db session
        db.session.commit() #save everythig in the session to the db

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def from_dict(self, data):
        self.email=data['email']
        self.password = self.hash_password(data['password'])

    def to_dict(self):
        return {
            'id':self.id,
            'email':self.email,
            'is_admin':self.is_admin,
            'token':self.token
        }

class Book(db.Model):
    book_id = db.Column(db.Integer, primary_key=True)
    title =  db.Column(db.String)
    author =  db.Column(db.String)
    pages = db.Column(db.Integer)
    summary = db.Column(db.Text)
    image = db.Column(db.String)
    subject =  db.Column(db.String)

    def __repr__(self):
        return f'<Book: {self.book_id}|{self.title}>'

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def to_dict(self):
        return {
            'id':self.book_id,
            'title':self.title,
            'author':self.author,
            'pages':self.pages,
            'summary':self.summary,
            'image':self.image,
            'subject':self.subject
        }

    def from_dict(self, data):
        for field in ['title','author','pages','summary','image','subject']:
            if field in data:
                    #the object, the attribute, value
                setattr(self, field, data[field])

################ Login and token auth#############

@app.get('/token')
@basic_auth.login_required()
def get_token():
    token = g.current_user.get_token()
    return make_response({"token":token}, 200)


@app.get('/login')
@basic_auth.login_required()
def get_login():
    user = g.current_user
    token  = user.get_token()
    return make_response({"token":token, **user.to_dict()},200)

############################## /user post put and delete ##############################

@app.post('/user')
def register_user():
    new_user = request.get_json() #this retrieves the payload/body
    user_dict = {
        "email":(new_user["email"]).lower(),
        "password":new_user["password"],
    }
    user = User()
    user.from_dict(user_dict)
    user.save()
    
    return make_response(f'User id: {user.id} created', 200)


@app.put('/user/<int:id>')
@token_auth.login_required()
def put_user(id):
    put_data = request.get_json()
    user = User.query.get(id)
    if not user:
        abort(404)

    new_email = request.get_json().get("email")
    new_password = request.get_json().get("password")

    user.email = new_email
    user.password = new_password

    user.save()
    return make_response(f'User ID: {user.id} has been changed', 200)


@app.delete('/user/<int:id>')
@token_auth.login_required()
def delete_user(id):
    user = User.query.get(id)
    if not user:
        abort(404)
    user.delete()
    return make_response(f"User {id} has been deleted", 200)


############################## /book http mathods ##############################

@app.get('/book')
def get_books():
    books = Book.query.all()
    book_dicts= [book.to_dict() for book in books]
    return make_response({"Books":book_dicts},200)

@app.get('/book/<int:id>')
def get_item(id):
    book = Book.query.get(id)
    if not book:
        abort(404)
    book_dict = book.to_dict()
    return make_response(book_dict,200)

@app.post("/book")
@token_auth.login_required()
@require_admin
def post_book():
    book_dict = request.get_json()
    if not all(key in book_dict for key in ('title','author','pages','summary','image','subject')):
        abort(400)
    
    book = Book()
    book.from_dict(book_dict)
    book.save()

    return make_response(f"Book {book.title} was created with an id {book.book_id}",200)

@app.put("/book/<int:id>")
@token_auth.login_required()
@require_admin
def put_book(id):
    book_dict = request.get_json()
    book = Book.query.get(id)
    if not book:
        abort(404)
    book.from_dict(book_dict)
    book.save()
    return make_response(f"Item {book.title} with ID {book.book_id} has been updated", 200)

@app.delete('/book/<int:id>')
@token_auth.login_required()
@require_admin
def delete_book(id):
    book_to_delete = Book.query.get(id)
    if not book_to_delete:
        abort(404)
    book_to_delete.delete()
    return make_response(f"Item with id: {id} has been delted", 200)

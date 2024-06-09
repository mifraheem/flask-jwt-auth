from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SUPER-SECRET-KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)
CORS(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()

class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']
        if not username or not password:
            return {'message': 'Please provide both username and password'}, 400
        if User.query.filter_by(username=username).first():
            return {'message': 'Username already exists'}, 400
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return {"message": "User created successfully"}, 201

class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}, 200
        else:
            return {"message": "Invalid credentials"}, 401

class UserWelcome(Resource):
    def get(self):
        return {"message": "Welcome to FLASK-JWT-AUTHENTICATION System"}

class ProtectedResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=current_user_id).first()
        return {"message": f"Hello, {user.username}!"}, 200

api.add_resource(UserWelcome, "/")
api.add_resource(ProtectedResource, "/protected")
api.add_resource(UserRegistration, "/register")
api.add_resource(UserLogin, "/login")

if __name__ == "__main__":
    app.run(debug=True)

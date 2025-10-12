from flask import request
from marshmallow import ValidationError
from flask.views import MethodView
from flask_jwt_extended import (
    jwt_required,
    create_access_token,
    get_jwt_identity,
    get_jwt
)
from passlib.hash import bcrypt

from app import db
from models import User, UserCredentials
from schemas import UserSchema, RegisterSchema, LoginSchema


class UserAPI(MethodView):
    @jwt_required()
    def get(self):
        claims = get_jwt()
        if claims["role"] != "admin":
            return {"error": "No autorizado"}, 403
        users = User.query.all()
        return UserSchema(many=True).dump(users)

    def post(self):
        try:
            data = UserSchema().load(request.json)
            new_user = User(
                name=data.get('name'),
                email=data.get('email')
            )
            db.session.add(new_user)
            db.session.commit()
        except ValidationError as err:
            return {"Errors": f"{err.messages}"}, 400
        return UserSchema().dump(new_user), 201


class UserDetailAPI(MethodView):

    @jwt_required()
    def get(self, id):
        current_user_id = int(get_jwt_identity())
        claims = get_jwt()
        if claims["role"] != "admin" and current_user_id != id:
            return {"error": "No autorizado"}, 403

        user = User.query.get_or_404(id)
        return UserSchema().dump(user), 200

    @jwt_required()
    def put(self, id):
        current_user_id = int(get_jwt_identity())
        claims = get_jwt()
        if claims["role"] != "admin" and current_user_id != id:
            return {"error": "No autorizado"}, 403

        user = User.query.get_or_404(id)
        try:
            data = UserSchema().load(request.json)
            user.name = data['name']
            user.email = data['email']
            db.session.commit()
            return UserSchema().dump(user), 200
        except ValidationError as err:
            return {"Error": err.messages}

    @jwt_required()
    def patch(self, id):
        current_user_id = int(get_jwt_identity())
        claims = get_jwt()
        if claims["role"] != "admin" and current_user_id != id:
            return {"error": "No autorizado"}, 403

        user = User.query.get_or_404(id)
        try:
            data = UserSchema(partial=True).load(request.json)
            if 'name' in data:
                user.name = data.get('name')
            if 'email' in data:
                user.email = data.get('email')
            db.session.commit()
            return UserSchema().dump(user), 200
        except ValidationError as err:
            return {"Error": err.messages}

    @jwt_required()
    def delete(self, id):
        current_user_id = int(get_jwt_identity())
        claims = get_jwt()

        if claims["role"] != "admin" and current_user_id != id:
            return {"error": "No autorizado"}, 403

        user = User.query.get_or_404(id)

        try:
            if hasattr(user, 'credential') and user.credential:
                db.session.delete(user.credential)
            
            db.session.delete(user)
            db.session.commit()
            return {"Message": "Deleted User"}, 204

        except Exception as e:
            return {"Error": f"No es posible borrarlo: {str(e)}"}, 500



class UserRegisterAPI(MethodView):
    def post(self):
        try:
            data = RegisterSchema().load(request.json)
        except ValidationError as err:
            return {"errors": err.messages}, 400  # ✅ ahora sí es serializable

        if User.query.filter_by(email=data['email']).first():
            return {"error": "Email en uso"}, 400

        new_user = User(name=data["name"], email=data['email'])
        db.session.add(new_user)
        db.session.flush()

        password_hash = bcrypt.hash(data['password'])
        credenciales = UserCredentials(
            user_id=new_user.id,
            password_hash=password_hash,
            role=data['role']
        )
        db.session.add(credenciales)
        db.session.commit()

        return UserSchema().dump(new_user), 201


class AuthLoginAPI(MethodView):
    def post(self):
        try:
            data = LoginSchema().load(request.json)
        except ValidationError as err:
            return {"errors": err.messages}, 400

        user = User.query.filter_by(email=data["email"]).first()
        if not user or not user.credential:
            return {"errors": {"credentials": ["Inválidas"]}}, 401

        if not bcrypt.verify(data["password"], user.credential.password_hash):
            return {"errors": {"credentials": ["Inválidas"]}}, 401

        token = create_access_token(
            identity=str(user.id),
            additional_claims={
                "email": user.email,
                "role": user.credential.role
            }
        )

        return {"access_token": token}, 200

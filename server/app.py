#!/usr/bin/env python3

from flask import jsonify, make_response, request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class userById(Resource):
    def delete(self, id):
        user = User.query.filter_by(id=id).first()
        db.session.delete(user)
        db.session.commit()

        return make_response({"message": "User deleted"}, 200)


class Signup(Resource):
    def post(self):
        json = request.get_json()
        user = User(
            username=json["username"],
            password_hash=json["password"],
            image_url=json["image_url"],
            bio=json["bio"]
        )
        db.session.add(user)
        db.session.commit()

        return user.to_dict(), 200


class CheckSession(Resource):
    pass


class Login(Resource):
    def post(self):
        username = request.get_json()["username"]
        password = request.get_json()["password"]

        user = User.query.filter(User.username == username).first()
        if user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 200

        return make_response({"Invalid username or password"}, 404)


class Logout(Resource):
    pass


class RecipeIndex(Resource):
    pass


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

api.add_resource(userById, "/users/<int:id>")


if __name__ == '__main__':
    app.run(port=5555, debug=True)

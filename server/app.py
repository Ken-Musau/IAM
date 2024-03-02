#!/usr/bin/env python3

from dis import Instruction
from flask import jsonify, make_response, request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Home(Resource):
    def get(self):
        return make_response("<h1>Welcome to IAM</h2>")


class Users(Resource):
    def get(self):
        users = [user.to_dict() for user in User.query.all()]
        return make_response(users, 200)


class UserById(Resource):

    def get(self, id):
        user = User.query.filter_by(id=id).first()

        if user:
            return user.to_dict(), 200

        return ["user not found"], 404

    def delete(self, id):
        user = User.query.filter_by(id=id).first()
        db.session.delete(user)
        db.session.commit()

        return make_response({"message": "User deleted"}, 200)


# Authentication

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

        return make_response(jsonify(user.to_dict()), 200)


class Login(Resource):
    def post(self):
        username = request.get_json()["username"]
        password = request.get_json()["password"]

        user = User.query.filter(User.username == username).first()
        if user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 200

        return make_response({"Invalid username or password"}, 404)


class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get("user_id")).first()

        if user:
            return user.to_dict(), 200
        return make_response([" Please Log in"])


class Logout(Resource):
    def delete(self):
        session["user_id"] = None

        return make_response(["Successfully logged out"], 200)


class RecipeIndex(Resource):
    def get(self):
        recipes = [recipe.to_dict() for recipe in Recipe.query.all()]

        return recipes, 200

    def post(self):
        json = request.get_json()
        new_recipe = Recipe(
            title=json["title"],
            instructions=json["instructions"],
            minutes_to_complete=json["minutes_to_complete"],
            user_id=session["user_id"]
        )

        db.session.add(new_recipe)
        db.session.commit()

        return new_recipe.to_dict(), 200


class RecipeById(Resource):
    def get(self, id):
        recipe = Recipe.query.filter_by(id=id).first()
        return recipe.to_dict(), 200

    def delete(self, id):
        recipe = Recipe.query.filter_by(id=id).first()
        db.session.delete(recipe)
        db.session.commit()

        return make_response(["Recipe DELETED"], 200)


class ClearSession(Resource):

    def delete(self):

        session['user_id'] = None

        return {}, 204


@app.before_request
def check_if_logged_in():
    open_access_list = [
        "home",
        "clear",
        "signup",
        "check_session",
        "login",
        "logout"

    ]

    if (request.endpoint) not in open_access_list and (not session.get("user_id")):
        return {'error': '401 Unauthorized'}, 401


api.add_resource(Home, "/", endpoint='home')

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')
api.add_resource(RecipeById, '/recipes/<int:id>',
                 endpoint='individual_recipe')

api.add_resource(UserById, "/users/<int:id>", endpoint="individual_users")
api.add_resource(Users, "/users", endpoint="users")

api.add_resource(ClearSession, "/clear", endpoint="clear")


if __name__ == '__main__':
    app.run(port=5555, debug=True)

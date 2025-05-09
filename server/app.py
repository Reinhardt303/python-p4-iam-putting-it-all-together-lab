#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        
        try:
            user = User(
                username=json['username'],
                image_url=json.get('image_url'),
                bio=json.get('bio')
            )
            user.password_hash = json['password']
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 201
        
        except (KeyError, ValueError, IntegrityError) as e:
            db.session.rollback()
            return {"error": f"Invalid signup: {str(e)}"}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }, 200
        return {'error': "Unauthorized"}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return {'error': 'Missing username or password'}, 400

        user = User.query.filter_by(username=data['username']).first()

        if user and user.authenticate(data['password']):
            session['user_id'] = user.id
            return {
                'id': user.id,
                'username': user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }, 200
        else:
            return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if user_id:
            session.pop('user_id', None)
            return {}, 204
        else:
            return {'error': 'Not logged in'}, 401

class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id') is None:
            return {'error': 'Unauthorized'}, 401

        recipes = Recipe.query.all()
        recipe_list = [{
            "title": recipe.title,
            "instructions": recipe.instructions,
            "minutes_to_complete": recipe.minutes_to_complete,
            "user": {
                "id": recipe.user.id,
                "username": recipe.user.username,
                "image_url": recipe.user.image_url,
                "bio": recipe.user.bio
            }
        } for recipe in recipes]
        return recipe_list, 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()

        title = data.get("title")
        instructions = data.get("instructions")
        minutes_to_complete = data.get("minutes_to_complete")

        errors = {}
        if not title:
            errors["title"] = "Title is required."
        if not instructions:
            errors["instructions"] = "Instructions are required."
        if not isinstance(minutes_to_complete, int):
            errors["minutes_to_complete"] = "Minutes to complete must be an integer."

        if errors:
            return {"errors": errors}, 422

        try:
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(new_recipe)
            db.session.commit()
        except (ValueError, IntegrityError) as e:
            db.session.rollback()
            return {"error": str(e)}, 422

        user = new_recipe.user

        return {
            "title": new_recipe.title,
            "instructions": new_recipe.instructions,
            "minutes_to_complete": new_recipe.minutes_to_complete,
            "user": {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }
        }, 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
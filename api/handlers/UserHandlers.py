#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
from datetime import datetime

from flask import g, request, make_response, render_template, redirect, url_for
from flask_restx import Resource

import api.error.errors as error
from api.conf.auth import auth, secret_key, enc_algo, pyjwt
from api.database.database import db
from api.models.models import Blacklist, User
from api.roles import role_required
from api.schemas.schemas import UserSchema


class Register(Resource):
    @staticmethod
    def post():
        print(request.get_json())
        try:
            username, password, email = (
                request.json.get("username").strip(),
                request.json.get("password").strip(),
                request.json.get("email").strip(),
            )
        except Exception as why:
            logging.info("Username, password or email is wrong. " + str(why))
            return error.INVALID_INPUT_422

        if username is None or password is None or email is None:
            return error.INVALID_INPUT_422

        user = User.query.filter_by(email=email).first()

        if user is not None:
            return error.ALREADY_EXIST


        user = User(username=username, password=password, email=email)
        db.session.add(user)
        db.session.commit()

        response = make_response(redirect(url_for("login_page")))
        
        return response


class Login(Resource):
    @staticmethod
    def post():
        try:
            email, password = (
                request.json.get("email").strip(),
                request.json.get("password").strip(),
            )
            
        except Exception as why:
            logging.info("Email or password is wrong. " + str(why))
            return error.INVALID_INPUT_422

        if email is None or password is None:
            return error.INVALID_INPUT_422

        user = User.query.filter_by(email=email, password=password).first()
        
        if user is None:
            return error.UNAUTHORIZED

        if user.user_role == "user":
            access_token = user.generate_auth_token(0)

        elif user.user_role == "admin":
            access_token = user.generate_auth_token(1)

        elif user.user_role == "sa":
            access_token = user.generate_auth_token(2)

        else:
            return error.INVALID_INPUT_422

        refresh_token = pyjwt.encode({"email": email}, secret_key, enc_algo)
        response = make_response(redirect(url_for("index_page")))
        response.set_cookie("access_token", access_token,   httponly=True, secure=True, samesite='lax')
        response.set_cookie("refresh_token", refresh_token, httponly=True, secure=True, samesite='lax')

        return response


class Logout(Resource):
    @staticmethod
    @auth.login_required
    def post():
        refresh_token = request.cookies.get("refresh_token")
        #ref = Blacklist.query.filter_by(refresh_token=refresh_token).first()
        #if ref is not None:
            #return {"status": "already invalidated", "refresh_token": refresh_token}
        #blacklist_refresh_token = Blacklist(refresh_token=refresh_token)
        #db.session.add(blacklist_refresh_token)
        #db.session.commit()
        #return {"status": "invalidated", "refresh_token": refresh_token}
        response = make_response(redirect(url_for("login_page")))
        response.set_cookie("access_token", "", max_age=0)
        response.set_cookie("refresh_token", "", max_age=0)
        return response
            

class RefreshToken(Resource):
    @staticmethod
    def post():

        # Get refresh token.
        refresh_token = request.json.get("refresh_token")

        # Get if the refresh token is in blacklist.
        ref = Blacklist.query.filter_by(refresh_token=refresh_token).first()

        # Check refresh token is existed.
        if ref is not None:

            # Return invalidated token.
            return {"status": "invalidated"}

        try:
            # Decoding request refresh_token
            data = pyjwt.decode(refresh_token, secret_key, algorithms=[enc_algo])

        except Exception as why:
            # Log the error.
            logging.error(why)

            # If it does not generated return false.
            return False

        # Create user not to add db. For generating token.
        user = User(email=data["email"])

        # New token generate.
        token = user.generate_auth_token(False)

        # Return new access token.
        return {"access_token": token}


class ResetPassword(Resource):
    @auth.login_required
    def post(self):

        # Get old and new passwords.
        old_pass, new_pass = request.json.get("old_pass"), request.json.get("new_pass")

        # Get user. g.user generates email address cause we put email address to g.user in models.py.
        user = User.query.filter_by(email=g.user).first()

        # Check if user password does not match with old password.
        if user.password != old_pass:

            # Return does not match status.
            return {"status": "old password does not match."}

        # Update password.
        user.password = new_pass

        # Commit session.
        db.session.commit()

        # Return success status.
        return {"status": "password changed."}


class UsersData(Resource):
    @auth.login_required
    @role_required.permission(2)
    def get(self):
        try:

            # Get usernames.
            usernames = (
                []
                if request.args.get("usernames") is None
                else request.args.get("usernames").split(",")
            )

            # Get emails.
            emails = (
                []
                if request.args.get("emails") is None
                else request.args.get("emails").split(",")
            )

            # Get start date.
            start_date = datetime.strptime(request.args.get("start_date"), "%d.%m.%Y")

            # Get end date.
            end_date = datetime.strptime(request.args.get("end_date"), "%d.%m.%Y")

            print(usernames, emails, start_date, end_date)

            # Filter users by usernames, emails and range of date.
            users = (
                User.query.filter(User.username.in_(usernames))
                .filter(User.email.in_(emails))
                .filter(User.created.between(start_date, end_date))
                .all()
            )

            # Create user schema for serializing.
            user_schema = UserSchema(many=True)

            # Get json data
            data, errors = user_schema.dump(users)

            # Return json data from db.
            return data

        except Exception as why:

            # Log the error.
            logging.error(why)

            # Return error.
            return error.INVALID_INPUT_422


# auth.login_required: Auth is necessary for this handler.
# role_required.permission: Role required user=0, admin=1 and super admin=2.


class DataUserRequired(Resource):
    @auth.login_required
    def get(self):

        return "Test user data."


class DataAdminRequired(Resource):
    @auth.login_required
    @role_required.permission(1)
    def get(self):

        return "Test admin data."


class DataSuperAdminRequired(Resource):
    @auth.login_required
    @role_required.permission(2)
    def get(self):

        return "Test super admin data."

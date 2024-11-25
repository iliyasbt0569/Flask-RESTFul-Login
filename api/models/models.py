#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import datetime

from flask import g, request

from api.conf.auth import auth, secret_key, enc_algo, pyjwt
from api.database.database import db


class User(db.Model):

    # Generates default class name for table. For changing use
    # __tablename__ = 'users'

    # User id.
    id = db.Column(db.Integer, primary_key=True)

    # User name.
    username = db.Column(db.String(length=80))

    # User password.
    password = db.Column(db.String(length=80))

    # User email address.
    email = db.Column(db.String(length=80))

    # Creation time for user.
    created = db.Column(db.DateTime, default=datetime.utcnow)

    # Unless otherwise stated default role is user.
    user_role = db.Column(db.String, default="user")

    def generate_auth_token(self, permission_level):
        payload = {"email": self.email, "username": self.username}

        # Check if admin
        if permission_level == 1:
            payload.update({"permission_level": 1})
            token = pyjwt.encode(payload, secret_key, enc_algo)
            return token
        
        # Check if superadmin
        elif permission_level == 2:
            payload.update({"permission_level": 2})
            token = pyjwt.encode(payload, secret_key, enc_algo)
            return token
        
        # Else default user
        payload.update({"permission_level": 0})
        return pyjwt.encode(payload, secret_key, enc_algo)

    # Generates a new access token from refresh token.
    @staticmethod
    @auth.verify_token
    def verify_auth_token(token):
        # Create a global none user.
        g.user = None
        token = request.cookies.get("access_token")
        try:
            # Load token.
            data = pyjwt.decode(token, secret_key, algorithms=[enc_algo])
        except:
            # If any error return false.
            return False

        # Check if email and admin permission variables are in jwt.
        if "email" and "permission_level" in data:

            # Set email from jwt.
            g.user = data["email"]

            # Set admin permission from jwt.
            g.permission_level = data["permission_level"]
            # Return true.
            return True

        # If does not verified, return false.
        return False

    def __repr__(self):

        # This is only for representation how you want to see user information after query.
        return "<User(id='%s', name='%s', password='%s', email='%s', created='%s')>" % (
            self.id,
            self.username,
            self.password,
            self.email,
            self.created,
        )


class Blacklist(db.Model):

    # Generates default class name for table. For changing use
    # __tablename__ = 'users'

    # Blacklist id.
    id = db.Column(db.Integer, primary_key=True)

    # Blacklist invalidated refresh tokens.
    refresh_token = db.Column(db.String(length=255))

    def __repr__(self):

        # This is only for representation how you want to see refresh tokens after query.
        return "<User(id='%s', refresh_token='%s', status='invalidated.')>" % (
            self.id,
            self.refresh_token,
        )

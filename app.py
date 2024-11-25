#!/usr/bin/python
# -*- coding: utf-8 -*-

import os

from flask import Flask, render_template, redirect, url_for, request
import werkzeug

from api.conf.auth import auth, secret_key, enc_algo, pyjwt
from api.conf.config import SQLALCHEMY_DATABASE_URI
from api.conf.routes import generate_routes
from api.database.database import db
from api.db_initializer.db_initializer import (create_admin_user,
                                               create_super_admin,
                                               create_test_user)

# Create a flask app.
app = Flask(__name__)

# Set debug true for catching the errors.
app.config['DEBUG'] = True

# Set database url.
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# Generate routes.
generate_routes(app)

# Database initialize with app.
db.init_app(app)

# Check if there is no database.
if not os.path.exists(SQLALCHEMY_DATABASE_URI):
    db.app = app
    with app.app_context():
        db.create_all()
        create_super_admin()
        create_admin_user()
        create_test_user()

@app.route('/login')
def login_page():
    try:
        token = request.cookies.get("access_token")
        data = pyjwt.decode(token, secret_key, algorithms=[enc_algo])
    except:
        return render_template("login.html")
    return redirect(url_for("index_page"))

@app.route('/register')
def register_page():
    try:
        token = request.cookies.get("access_token")
        data = pyjwt.decode(token, secret_key, algorithms=[enc_algo])
    except:
        return render_template("register.html")
    return redirect(url_for("index_page"))

@app.route('/index')
@auth.login_required
def index_page():
    token = request.cookies.get("access_token")
    data = pyjwt.decode(token, secret_key, algorithms=[enc_algo])

    return render_template("index.html", token_data=data)

@app.errorhandler(404)
def handle_bad_request(e):
    return 'bad request!', 400

@app.errorhandler(401)
def handle_bad_request(e):
    return redirect(url_for("login_page"))

app.run()
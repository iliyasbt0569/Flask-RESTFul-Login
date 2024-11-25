#!/usr/bin/python
# -*- coding: utf-8 -*-

from flask_httpauth import HTTPTokenAuth

import jwt as pyjwt

secret_key = "ErFdc[]dfD"
enc_algo = "HS256"

# Auth object creation.
auth = HTTPTokenAuth("Bearer")


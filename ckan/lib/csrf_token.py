# -*- coding: utf-8 -*-

import os
import base64
import struct
import random
from pylons import session
from ckan.common import c

import logging
log = logging.getLogger(__name__)

class CsrfTokenValidationError(Exception):
    pass

def _get_current_token(user):
    tokens = session.get('csrf_tokens', {})
    return tokens.get(user, None)

def _set_current_token(user, token):
    tokens = session.get('csrf_tokens', {})
    tokens[user] = token
    session['csrf_tokens'] = tokens
    session.save()

def _generate_new_token():
    token_bytes = os.urandom(64)
    token = base64.urlsafe_b64encode(token_bytes)
    return token

def _get_user():
    return c.user

# Compare tokens in random order to avoid timing attacks
def _compare_tokens(a, b):
    if not a or not b or len(a) != len(b):
        return False

    indices = range(len(a))
    random.shuffle(indices)

    for i in indices:
        if a[i] != b[i]:
            return False

    return True

def generate():
    user = _get_user()
    if not user: return ''

    existing_token = _get_current_token(user)
    if existing_token:
        return existing_token

    token = _generate_new_token()
    _set_current_token(user, token)
    return token

def validate(token):
    user = _get_user()
    if not user:
        raise CsrfTokenValidationError()

    existing_token = _get_current_token(user)
    if not _compare_tokens(token, existing_token):
        raise CsrfTokenValidationError()

# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

import time
from datetime import datetime

from google.appengine.ext import ndb

from webapp2_extras.appengine.auth.models import User as AuthUser
from webapp2_extras.security import generate_password_hash


class User(AuthUser):
    """
    Derived from appengine.auth.models.User, which contains auth_ids,
    a collection of strings that each represents a unique identifier
    for the user. Examples:

        - own:username
        - google:email
        - facebook:facebook_uid

    Encrypted password is stored in appengine.auth.models.User alongside
    created and updated timestamp fields.
    """

    email = ndb.StringProperty(
        required=True)
    name = ndb.StringProperty(
        required=True)
    image_url = ndb.StringProperty()
    country = ndb.StringProperty(
        required=True)
    active = ndb.BooleanProperty(
        required=True,
        default=True)
    verified = ndb.BooleanProperty(
        required=True,
        default=False)

    def set_password(self, raw_password):
        """
        Sets the password for the current user

        :param raw_password:
            The raw password which will be hashed and stored
        """
        self.password = generate_password_hash(raw_password, length=12)

    def unverified_days(self):
        """
        Returns number of days account has been unverified.
        """
        age = datetime.now() - self.created
        return None if self.verified else age.days

    @classmethod
    def get_by_auth_token(cls, user_id, token, subject='auth'):
        """
        Returns a user object based on a user ID and token.

        :param user_id:
            The user_id of the requesting user.
        :param token:
            The token string to be verified.
        :returns:
            A tuple ``(User, timestamp)``, with a user object and
            the token timestamp, or ``(None, None)`` if both were not found.
        """
        token_key = cls.token_model.get_key(user_id, subject, token)
        user_key = ndb.Key(cls, user_id)
        # Use get_multi() to save a RPC call.
        valid_token, user = ndb.get_multi([token_key, user_key])
        if valid_token and user:
            timestamp = int(time.mktime(valid_token.created.timetuple()))
            return user, timestamp
        return None, None


class SocialUser(ndb.Model):
    """
    Stores social information for federated logins.
    """

    user = ndb.KeyProperty(
        required=True,
        kind=User)
    provider = ndb.StringProperty(
        required=True)
    uid = ndb.StringProperty(
        required=True)
    extra_data = ndb.JsonProperty()

    @classmethod
    def get_by_user(cls, user):
        return cls.query(cls.user == user).fetch()

    @classmethod
    def get_by_user_and_provider(cls, user, provider):
        return cls.query(cls.user == user, cls.provider == provider).get()

    @classmethod
    def get_by_provider_and_uid(cls, provider, uid):
        return cls.query(cls.provider == provider, cls.uid == uid).get()

# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

from __future__ import absolute_import
import logging

from webapp2 import uri_for

from libs import *
import httplib2
from apiclient.discovery import build
from oauth2client.client import OAuth2WebServerFlow

from models.user import SocialUser


class GoogleError(Exception):
    pass


class Google(object):

    CLIENT_ID = '999999999999999'
    CLIENT_SECRET = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

    @classmethod
    def _server_flow(cls):
        callback_url = uri_for(
            'social_login_complete',
            provider_name='google',
            _full=True)
        return OAuth2WebServerFlow(
            client_id=cls.CLIENT_ID,
            client_secret=cls.CLIENT_SECRET,
            scope='profile email',
            redirect_uri=callback_url)

    @classmethod
    def auth_url(cls):
        try:
            return cls._server_flow().step1_get_authorize_url()
        except Exception, e:
            raise GoogleError('Google auth failure: %s' % (e,))

    @classmethod
    def login(cls, code, user):
        try:
            credentials = cls._server_flow().step2_exchange(code)
            service = build('plus', 'v1')
            http = credentials.authorize(httplib2.Http())
            info = service.people().get(userId='me').execute(http=http)
        except Exception:
            raise GoogleError('No user authentication information received')

        account_email = info.get('emails')[0] if info.get('emails') else None
        image = info.get('image')

        user_data = {
            'uid': credentials.id_token['sub'],
            'email': account_email.get('value') if account_email else None,
            'name': info.get('displayName'),
            'image_url': image.get('url').strip('\?sz=50') if image else None}

        if not all(user_data.values()):
            raise GoogleError('Required Google fields not available')

        social_user = SocialUser.get_by_provider_and_uid(
            provider='google',
            uid=user_data.get('uid'))

        if social_user:
            # login with google
            if user and social_user.user.id() != user.key.id():
                raise GoogleError('Google account already in use')
            user = social_user.user.get()
        elif user:
            # new association with google
            social_user = SocialUser(
                user=user.key,
                provider='google',
                uid=user_data.get('uid'),
                extra_data=user_data)
            social_user.put()
            logging.info('google: association added: %d', user.key.id())

        return user, user_data

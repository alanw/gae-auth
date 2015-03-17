# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

import logging

from webapp2 import uri_for

from libs import *
from libs.facebook import facebook

from models.user import SocialUser


class FacebookError(Exception):
    pass


class Facebook(object):

    API_KEY = '999999999999999'
    API_SECRET = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

    @classmethod
    def auth_url(cls):
        try:
            callback_url = uri_for(
                'social_login_complete',
                provider_name='facebook',
                _full=True)
            return facebook.auth_url(
                app_id=cls.API_KEY,
                canvas_url=callback_url,
                perms=['email', 'public_profile'])
        except Exception, e:
            raise FacebookError('Facebook auth failure: %s' % (e,))

    @classmethod
    def login(cls, code, user):
        try:
            callback_url = uri_for(
                'social_login_complete',
                provider_name='facebook',
                _full=True)
            access_token = facebook.get_access_token_from_code(
                code=code,
                redirect_uri=callback_url,
                app_id=cls.API_KEY,
                app_secret=cls.API_SECRET)
            graph_api = facebook.GraphAPI(access_token['access_token'])
            info = graph_api.get_object('me')
        except Exception, e:
            raise FacebookError('Facebook access token failure: %s' % (e,))

        image_url = 'http://graph.facebook.com/{uid}/picture?type=large'.format(
            uid=str(info.get('id')))

        user_data = {
            'uid': str(info.get('id')),
            'email': info.get('email'),
            'name': info.get('name'),
            'image_url': image_url}

        if not all(user_data.values()):
            raise FacebookError('Required Facebook fields not available')

        social_user = SocialUser.get_by_provider_and_uid(
            provider='facebook',
            uid=user_data.get('uid'))

        if social_user:
            # login with facebook
            if user and social_user.user.id() != user.key.id():
                raise FacebookError('Facebook account already in use')
            user = social_user.user.get()
        elif user:
            # new association with facebook
            social_user = SocialUser(
                user=user.key,
                provider='facebook',
                uid=user_data.get('uid'),
                extra_data=user_data)
            social_user.put()
            logging.info('facebook: association added: %d', user.key.id())

        return user, user_data

# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

from webapp2 import uri_for

from libs import *
import facebook_api

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
            return facebook_api.auth_url(
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
            access_token = facebook_api.get_access_token_from_code(
                code=code,
                redirect_uri=callback_url,
                app_id=cls.API_KEY,
                app_secret=cls.API_SECRET)
            graph_api = facebook_api.GraphAPI(access_token['access_token'])
            user_data = graph_api.get_object('me')
            user_data['uid'] = str(user_data.get('id'))
        except Exception, e:
            raise FacebookError('Facebook access token failure: %s' % (e,))

        uid = str(user_data.get('id'))
        email = user_data.get('email')
        name = user_data.get('name')
        if not all((uid, email, name)):
            raise FacebookError('Required Facebook fields not available')

        if user:
            # new association with facebook
            unique_uid = SocialUser.check_unique(
                user=user.key.id(),
                provider='facebook',
                uid=uid)
            if unique_uid:
                social_user = SocialUser(
                    user=user.key.id(),
                    provider='facebook',
                    uid=uid,
                    extra_data=user_data)
                social_user.put()
                logging.info('facebook: association added: %s', uid)
            else:
                raise FacebookError('Facebook account already in use')
        else:
            # login with facebook
            social_user = SocialUser.get_by_provider_and_uid(
                provider='facebook',
                uid=uid)
            user = social_user.user.get() if social_user else None

        return user, user_data
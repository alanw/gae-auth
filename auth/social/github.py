# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

import logging

from webapp2 import uri_for

from libs import *
from libs.github import github

from models.user import SocialUser


class GithubError(Exception):
    pass


class Github(object):

    CLIENT_ID = '999999999999999'
    CLIENT_SECRET = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

    @classmethod
    def _github_auth(cls):
        callback_url = uri_for(
            'social_login_complete',
            provider_name='github',
            _full=True)
        return github.GithubAuth(
            github_server='github.com',
            github_client_id=cls.CLIENT_ID,
            github_client_secret=cls.CLIENT_SECRET,
            github_redirect_uri=callback_url,
            scope='user')

    @classmethod
    def auth_url(cls):
        try:
            return cls._github_auth().get_authorize_url()
        except Exception, e:
            raise GithubError('Github auth failure: %s' % (e,))

    @classmethod
    def login(cls, code, user):
        try:
            access_token = cls._github_auth().get_access_token(code)
            info = github_auth.get_user_info(access_token)

        except Exception, e:
            raise GithubError('Github access token failure: %s' % (e,))

        user_data = {
            'uid': info.get('login'),
            'email': info.get('email'),
            'name': info.get('name'),
            'image_url': info.get('avatar_url')}

        if not all(user_data.values()):
            raise GithubError('Required Github fields not available')

        social_user = SocialUser.get_by_provider_and_uid(
            provider='github',
            uid=user_data.get('uid'))

        if social_user:
            # login with github
            if user and social_user.user.id() != user.key.id():
                raise GithubError('Github account already in use')
            user = social_user.user.get()
        elif user:
            # new association with github
            social_user = SocialUser(
                user=user.key,
                provider='github',
                uid=user_data.get('uid'),
                extra_data=user_data)
            social_user.put()
            logging.info('github: association added: %d', user.key.id())

        return user, user_data

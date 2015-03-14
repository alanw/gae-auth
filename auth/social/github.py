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
    def auth_url(cls):
        try:
            callback_url = uri_for(
                'social_login_complete',
                provider_name='github',
                _full=True)
            github_auth = github.GithubAuth(
                github_server='github.com',
                github_client_id=cls.CLIENT_ID,
                github_client_secret=cls.CLIENT_SECRET,
                github_redirect_uri=callback_url,
                scope='user')
            return github_auth.get_authorize_url()
        except Exception, e:
            raise GithubError('Github auth failure: %s' % (e,))

    @classmethod
    def login(cls, code, user):
        try:
            callback_url = uri_for(
                'social_login_complete',
                provider_name='github',
                _full=True)
            github_auth = github.GithubAuth(
                github_server='github.com',
                github_client_id=cls.CLIENT_ID,
                github_client_secret=cls.CLIENT_SECRET,
                github_redirect_uri=callback_url,
                scope='user')
            access_token = github_auth.get_access_token(code)

            logging.info('DEBUG: access_token: %r', access_token)

            user_data = github_auth.get_user_info(access_token)

            logging.info('DEBUG: user_data from access_token: %r', user_data)
            user_data['uid'] = user_data.get('login')
        except Exception, e:
            raise GithubError('Github access token failure: %s' % (e,))

        # todo: this is the same as the facebook impl - maybe move to account.py?

        uid = user_data.get('login')
        email = user_data.get('email')
        name = user_data.get('name')
        if not all((uid, email, name)):
            raise GithubError('Required Github fields not available')

        logging.info('DEBUG: uid: %r', uid)
        logging.info('DEBUG: email: %r', email)
        logging.info('DEBUG: name: %r', name)
        logging.info('DEBUG: user: %r', user)

        social_user = SocialUser.get_by_provider_and_uid(
            provider='github',
            uid=uid)

        if social_user:
            # login with github
            logging.info('DEBUG: login with github: %r', social_user.user.id())
            logging.info('DEBUG: github user_data: %r', social_user.extra_data)
            if user and social_user.user.id() != user.key.id():
                raise GithubError('Github account already in use')
            user = social_user.user.get()
        elif user:
            logging.info('DEBUG: new assoc with github: %r', user.key)
            # new association with github
            social_user = SocialUser(
                user=user.key,
                provider='github',
                uid=uid,
                extra_data=user_data)
            social_user.put()
            logging.info('github: association added: %s', uid)

        return user, user_data

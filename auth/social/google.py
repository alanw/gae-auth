# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

from __future__ import absolute_import
import logging
import urllib2

from google.appengine.api import users
from webapp2 import uri_for
from webapp2_extras import json

from libs import *
import httplib2
from apiclient.discovery import build
from apiclient import discovery
from oauth2client.client import OAuth2WebServerFlow

from models.user import SocialUser


class GoogleError(Exception):
    pass


class Google(object):

    API_KEY = 'AIzaSyCG9D3lqwRg4IqaSAOT0up_r4Kf4h1LQEg'

    CLIENT_ID = '999999999999999'
    CLIENT_SECRET = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

    @classmethod
    def auth_url(cls):
        try:
            callback_url = uri_for(
                'social_login_complete',
                provider_name='google',
                _full=True)
            flow = OAuth2WebServerFlow(
                client_id=cls.CLIENT_ID,
                client_secret=cls.CLIENT_SECRET,
                scope='profile email',
                redirect_uri=callback_url)
            return flow.step1_get_authorize_url()
        except Exception, e:
            raise GoogleError('Google auth failure: %s' % (e,))

    @classmethod
    def login(cls, code, user):
        try:
            callback_url = uri_for(
                'social_login_complete',
                provider_name='google',
                _full=True)
            flow = OAuth2WebServerFlow(
                client_id=cls.CLIENT_ID,
                client_secret=cls.CLIENT_SECRET,
                scope='profile email',
                redirect_uri=callback_url)
            credentials = flow.step2_exchange(code)
            uid = credentials.id_token['sub']
        except Exception:
            raise GoogleError('No user authentication information received')

        logging.info('DEBUG: uid: %r', uid)
        logging.info('DEBUG: id_token: %r', credentials.id_token)

        access_token = credentials.access_token
        logging.info('DEBUG: access_token: %r', access_token)

        service = build('plus', 'v1')
        http = credentials.authorize(httplib2.Http())
        user_data = service.people().get(userId='me').execute(http=http)

        logging.info('DEBUG: user_data: %r', user_data)

        account_email = user_data.get('emails')[0] if user_data.get('emails') else None
        email = account_email.get('value') if account_email else None
        name = user_data.get('displayName')
        if not all((uid, email, name)):
            raise GoogleError('Required Google fields not available')

        user_data['uid'] = uid
        user_data['name'] = name
        user_data['email'] = email

        logging.info('DEBUG: uid: %r', uid)
        logging.info('DEBUG: email: %r', email)
        logging.info('DEBUG: name: %r', name)
        logging.info('DEBUG: user: %r', user)

        social_user = SocialUser.get_by_provider_and_uid(
            provider='google',
            uid=uid)

        if social_user:
            # login with google
            logging.info('DEBUG: login with google: %r', social_user.user.id())
            logging.info('DEBUG: google user_data: %r', social_user.extra_data)
            if user and social_user.user.id() != user.key.id():
                raise GoogleError('Google account already in use')
            user = social_user.user.get()
        elif user:
            logging.info('DEBUG: new assoc with google: %r', user.key)
            # new association with google
            social_user = SocialUser(
                user=user.key,
                provider='google',
                uid=uid,
                extra_data=user_data)
            social_user.put()
            logging.info('google: association added: %s', uid)

        return user, user_data



        # current_user = users.get_current_user()
        # if not current_user:
        #     raise GoogleError('No user authentication information received')

        # try:
        #     uid = current_user.user_id()
        #     email = current_user.email()

        #     logging.info('DEBUG: uid: %r', uid)
        #     logging.info('DEBUG: email: %r', email)

        #     # DEBUG, todo:
        #     # url = 'https://www.googleapis.com/plus/v1/people/me?access_token=' + self.request.get('token')
        #     # url = 'https://www.googleapis.com/plus/v1/people/113220740208420441429?key=AIzaSyCG9D3lqwRg4IqaSAOT0up_r4Kf4h1LQEg'
        #     # 118379778730776224064 - alan@spotify.com
        #     # 107030754624920700903 - alice
        #     # https://www.googleapis.com/plus/v1/people/107030754624920700903?key=AIzaSyCG9D3lqwRg4IqaSAOT0up_r4Kf4h1LQEg
        #     # https://www.googleapis.com/plus/v1/people/118379778730776224064?key=AIzaSyCG9D3lqwRg4IqaSAOT0up_r4Kf4h1LQEg
        #     url = 'https://www.googleapis.com/plus/v1/people/me?key=AIzaSyCG9D3lqwRg4IqaSAOT0up_r4Kf4h1LQEg'
        #     # 113220740208420441429
        #     # 102953885117845147435 - alanwright.home

        #     response = urllib2.urlopen(url)
        #     user_data = json.decode(response.read())

        #     logging.info('DEBUG: user_data: %r', user_data)
        # except Exception, e:
        #     raise GoogleError('Google API failure: %s' % (e,))

        # name = current_user.nickname()

        # logging.info('DEBUG: name: %r', name)

        # # todo: this is the same as the google impl - maybe move to account.py?
        # if not all((uid, email, name)):
        #     raise GoogleError('Required Google fields not available')

        # user_data = {
        #     'uid': uid,
        #     'email': email,
        #     'name': name}

        # logging.info('DEBUG: user: %r', user)

        # social_user = SocialUser.get_by_provider_and_uid(
        #     provider='google',
        #     uid=uid)

        # if social_user:
        #     # login with google
        #     logging.info('DEBUG: login with google: %r', social_user.user.id())
        #     logging.info('DEBUG: google user_data: %r', social_user.extra_data)
        #     if user and social_user.user.id() != user.key.id():
        #         raise GoogleError('Google account already in use')
        #     user = social_user.user.get()
        # elif user:
        #     logging.info('DEBUG: new assoc with google: %r', user.key)
        #     # new association with google
        #     social_user = SocialUser(
        #         user=user.key,
        #         provider='google',
        #         uid=uid,
        #         extra_data=user_data)
        #     social_user.put()
        #     logging.info('google: association added: %s', uid)

        # return user, user_data

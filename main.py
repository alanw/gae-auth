# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

import os
import logging
import webapp2
from datetime import timedelta

from webapp2_extras.routes import RedirectRoute
from google.appengine.api.app_identity import get_application_id

from handlers import account

# a staging environment is a place where features may be tested.
staging = get_application_id().endswith('staging')
debug = os.environ.get('SERVER_SOFTWARE', '').startswith('Dev') or staging

config = {
    'debug': debug,
    'webapp2_extras.auth': {
        'user_model': 'models.user.User',
        'user_attributes': ['email', 'name']},
    'webapp2_extras.sessions': {
        'secret_key': 'cf7386a75abc42db93cf11f28e4a0f18'},
    'csrf': {
        'enabled': True,
        'secret_key': '64164fe0b5e14e3f88e2c1854f4094f2',
        'time_limit': timedelta(hours=24)},
}

# turn on debugging logging for non-production
if debug:
    logging.getLogger().setLevel(logging.DEBUG)

app = webapp2.WSGIApplication([
    RedirectRoute('/signup', account.SignupHandler, name='signup', strict_slash=True),
    RedirectRoute('/verify/<user_id:\d+>/<token:.+>', handler=account.VerifyHandler, name='verify_token', strict_slash=True),
    RedirectRoute('/login', account.LoginHandler, name='login', strict_slash=True),
    RedirectRoute('/social_login/<provider_name:.+>/complete', account.CallbackSocialLoginHandler, name='social_login_complete', strict_slash=True),
    RedirectRoute('/social_login/<provider_name:.+>', account.SocialLoginHandler, name='social_login', strict_slash=True),
    RedirectRoute('/logout', account.LogoutHandler, name='logout', strict_slash=True),
    RedirectRoute('/forgot', account.ForgotHandler, name='forgot', strict_slash=True),
    RedirectRoute('/reset/<user_id:\d+>/<token:.+>', handler=account.ResetHandler, name='reset_token', strict_slash=True),
    RedirectRoute('/reset', account.ResetHandler, name='reset', strict_slash=True),
    RedirectRoute('/account/<user_id:\d+>/<action:.+>', account.AccountHandler, name='account', strict_slash=True),
], debug=debug, config=config)

# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

from base import BaseHandler, user_required

from auth.account import Account, AccountError, UnauthorizedError


class SignupHandler(BaseHandler):

    def post(self):
        try:
            user = Account.signup(
                email=self.request.POST.get('email'),
                name=self.request.POST.get('name'),
                password=self.request.POST.get('password'),
                country=self.country)

            # store user data in the session
            user_dict = self.auth.store.user_to_dict(user)
            self.auth.set_session(user=user_dict, remember=True)

            self.response.set_status(201)  # CREATED

        except AccountError, e:
            self.abort(code=e.code, detail=e.message)


class VerifyHandler(BaseHandler):

    def get(self, *args, **kwargs):
        try:
            user = Account.verify_email(
                user_id=kwargs.get('user_id'),
                token=kwargs.get('token'))
        except AccountError, e:
            self.abort(code=e.code, detail=e.message)

        # store user data in the session
        user_dict = self.auth.store.user_to_dict(user)
        self.auth.set_session(user=user_dict, remember=True)


class LoginHandler(BaseHandler):

    def post(self):
        # during a login attempt, invalidate current session
        self.auth.unset_session()

        try:
            user = Account.login(
                email=self.request.POST.get('email'),
                password=self.request.POST.get('password'))
        except AccountError, e:
            self.abort(code=e.code, detail=e.message)

        # create a new token with new timestamp
        user_dict = self.auth.store.user_to_dict(user)
        self.auth.set_session(user=user_dict, remember=True)


class SocialLoginHandler(BaseHandler):

    def get(self, *args, **kwargs):
        # remove all provider tokens before we begin
        [self.session.pop(provider, None) for provider in Account.PROVIDERS]

        try:
            redirect_uri = Account.social_login(
                provider_name=kwargs.get('provider_name'))
        except AccountError, e:
            self.abort(code=e.code, detail=e.message)

        # redirect to federated login
        self.redirect(redirect_uri)


class CallbackSocialLoginHandler(BaseHandler):

    def get(self, *args, **kwargs):
        try:
            user = Account.social_login_callback(
                provider_name=kwargs.get('provider_name'),
                params=dict(self.request.GET.items()),
                user=self.user,
                country=self.country)
        except AccountError, e:
            self.abort(code=e.code, detail=e.message)

        # create a new token with new timestamp
        user_dict = self.auth.store.user_to_dict(user)
        self.auth.set_session(user=user_dict, remember=True)


class LogoutHandler(BaseHandler):

    def get(self):
        # simply invalidate the session to logout
        self.auth.unset_session()


class ForgotHandler(BaseHandler):

    @user_required
    def post(self):
        try:
            Account.forgot_password(
                user=self.user,
                email=self.request.POST.get('email'))
        except AccountError, e:
            self.abort(code=e.code, detail=e.message)


class ResetHandler(BaseHandler):

    def get(self, *args, **kwargs):
        try:
            user = Account.verify_reset(
                user_id=kwargs.get('user_id'),
                token=kwargs.get('token'))
        except AccountError, e:
            self.abort(code=e.code, detail=e.message)

        # store user data in the session
        user_dict = self.auth.store.user_to_dict(user)
        self.auth.set_session(user=user_dict, remember=True)

        # return a form to be used to change their password
        # this form must include the token

    @user_required
    def post(self):
        try:
            Account.reset_password(
                user=self.user,
                token=self.request.POST.get('token'),
                password=self.request.POST.get('password'))
        except AccountError, e:
            self.abort(code=e.code, detail=e.message)


class AccountHandler(BaseHandler):

    @user_required
    def post(self, *args, **kwargs):
        try:
            user_id = kwargs.get('user_id')
            if int(user_id) != self.user.key.id():
                raise UnauthorizedError()
            user = None
            action = kwargs.get('action')
            if action == 'deactivate':
                Account.deactivate(user=self.user)
                self.auth.unset_session()
            elif action == 'name':
                user = Account.change_name(
                    user=self.user,
                    name=self.request.POST.get('name'))
            elif action == 'email':
                user = Account.change_email(
                    user=self.user,
                    email=self.request.POST.get('email'),
                    password=self.request.POST.get('password'))
            elif action == 'password':
                Account.change_password(
                    user=self.user,
                    old_password=self.request.POST.get('old_password'),
                    new_password=self.request.POST.get('new_password'))
            if user is not None:
                self.auth.set_session(
                    user=self.auth.store.user_to_dict(user),
                    remember=True)
        except AccountError, e:
            self.abort(code=e.code, detail=e.message)

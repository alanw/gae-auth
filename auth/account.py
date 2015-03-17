# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

import logging
from datetime import datetime, timedelta

from webapp2 import uri_for
from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError

from social.facebook import Facebook, FacebookError
from social.google import Google, GoogleError
from social.github import Github, GithubError
from common.email_helper import EmailHelper
from models.user import User, SocialUser


class AccountError(Exception):
    def __init__(self, code, message=None):
        self.code = code
        self.message = message


class BadRequestError(AccountError):
    def __init__(self, message=None):
        self.code = 400
        self.message = message


class NotFoundError(AccountError):
    def __init__(self, message=None):
        self.code = 404
        self.message = message


class UnauthorizedError(AccountError):
    def __init__(self, message=None):
        self.code = 401
        self.message = message


class InternalError(AccountError):
    def __init__(self, message=None):
        self.code = 503
        self.message = message


class DuplicateError(AccountError):
    def __init__(self, message=None):
        self.code = 409
        self.message = message


class Account(object):

    PROVIDERS = ['facebook', 'google', 'github']

    @classmethod
    def signup(cls, email, name, password, country):
        if not all((email, name, password, country)):
            raise BadRequestError('Must supply email, name, password and country')
        try:
            existing = User.get_by_auth_id('auth:' + email)

            # first we check whether we're attempting to reactivate a user
            if existing is not None and not existing.active:
                created, user = cls._reactivate_user(
                    user=existing,
                    name=name,
                    password=password)
            else:
                created, user = cls._create_user(
                    auth_id='auth:' + email,
                    email=email,
                    name=name,
                    country=country,
                    password=password)
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        if not created:
            if 'email' in user:
                raise DuplicateError('Email is already in use: %s' % (email,))
            raise InternalError('Internal storage failure: %s' % (email,))

        # generate signup token and send verify email
        cls._send_verify_email(user.get_id(), email, name)

        logging.info('account: new user: %s, %s', email, name)

        return user

    @classmethod
    def _reactivate_user(cls, user, name=None, password=None, image_url=None, verified=False):
        user.active = True
        user.name = name
        if password is not None:
            user.set_password(password)
        if image_url is not None:
            user.image_url = image_url
        user.verified = verified
        user.put()
        return True, user

    @classmethod
    def _create_user(cls, auth_id, email, name, country, image_url=None, password=None, verified=False):
        create_args = {
            'auth_id': auth_id,
            'unique_properties': ['email'],
            'email': email,
            'name': name,
            'country': country,
            'active': True,
            'verified': verified}
        if image_url:
            create_args['image_url'] = image_url
        if password:
            create_args['password_raw'] = password
        return User.create_user(**create_args)

    @classmethod
    def _send_verify_email(cls, user_id, email, name):
        try:
            token = User.create_signup_token(user_id)
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        # generate the url that a user clicks to verify their email
        verify_url = uri_for(
            'verify_token',
            user_id=user_id,
            token=token,
            _full=True)

        logging.info('account: verify link for %s: %s', email, verify_url)

        try:
            EmailHelper.verify_email(email=email, name=name, url=verify_url)
        except Exception, e:
            raise InternalError('Unable to send verification email: %s' % (e,))

    @classmethod
    def verify_email(cls, user_id, token):
        if not all((user_id, token)):
            raise BadRequestError('Must supply user and token')
        try:
            user, _ = User.get_by_auth_token(
                int(user_id),
                token,
                'signup')
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        if not user or not user.active:
            raise NotFoundError('Could not find any user for "%s" and token "%s"' % (user_id, token))

        try:
            # remove signup token, we don't want users to come back with an old link
            User.delete_signup_token(user.get_id(), token)

            # mark the user as verified
            if not user.verified:
                user.verified = True
                user.put()
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        logging.info('account: email verified: %s', user.email)

        return user

    @classmethod
    def login(cls, email, password):
        if not all((email, password)):
            raise BadRequestError('Must supply email and password')
        try:
            user = User.get_by_auth_password(
                auth_id='auth:' + email,
                password=password)
            if user is not None:
                if not user.active:
                    raise UnauthorizedError('Invalid email or password')
                elif not user.verified and user.created + timedelta(days=1) < datetime.now():
                    raise UnauthorizedError('Email not verified')
        except (InvalidAuthIdError, InvalidPasswordError):
            raise UnauthorizedError('Invalid email or password')
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        logging.info('account: auth user: %s', user.email)

        return user

    @classmethod
    def social_login(cls, provider_name):

        if provider_name == 'facebook':
            redirect_uri = Facebook.auth_url()
        elif provider_name == 'google':
            redirect_uri = Google.auth_url()
        elif provider_name == 'github':
            redirect_uri = Github.auth_url()
        else:
            raise NotFoundError('Authentication method not supported')

        logging.info('account: social auth url: %s', redirect_uri)

        return redirect_uri

    @classmethod
    def social_login_callback(cls, provider_name, params, user, country):
        if not provider_name:
            raise BadRequestError('Must supply a provider')
        try:
            if provider_name == 'facebook':
                user, user_data = Facebook.login(
                    code=params.get('code'),
                    user=user)
            elif provider_name == 'google':
                user, user_data = Google.login(
                    code=params.get('code'),
                    user=user)
            elif provider_name == 'github':
                user, user_data = Github.login(
                    code=params.get('code'),
                    user=user)
            else:
                raise NotFoundError('Authentication method not supported')

            if user:
                # reactivate a user if required
                if not user.active:
                    cls._reactivate_user(
                        user=user,
                        name=user_data.get('name'),
                        verified=True)
            else:
                user = cls._create_social_user(
                    provider_name=provider_name,
                    user_data=user_data,
                    country=country)
        except (FacebookError, GoogleError, GithubError) as e:
            raise InternalError('Federated login failure: %s' % (e,))
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        logging.info('account: social auth user: %s', user_data.get('uid'))

        return user

    @classmethod
    def _create_social_user(cls, provider_name, user_data, country):
        social_user = SocialUser.get_by_provider_and_uid(
            provider=provider_name,
            uid=user_data.get('uid'))
        if social_user is not None:
            raise UnauthorizedError('Account already in use: ' + user_data.get('uid'))

        created, user = cls._create_user(
            auth_id=provider_name + ':' + user_data.get('uid'),
            email=user_data.get('email'),
            name=user_data.get('name'),
            image_url=user_data.get('image_url'),
            country=country,
            verified=True)

        if not created:
            if 'email' in user:
                raise DuplicateError('Email is already in use: %s' % (user_data.get('email'),))
            raise InternalError('Internal storage failure: %s' % (user_data.get('email'),))

        # create social user and associate with user
        social_user = SocialUser(
            user=user.key,
            provider=provider_name,
            uid=user_data.get('uid'),
            extra_data=user_data)

        social_user.put()

        return user

    @classmethod
    def forgot_password(cls, user, email):
        if not email:
            raise BadRequestError('Must supply email')
        if user.email != email:
            raise UnauthorizedError()

        # generate token and send reset password email
        cls._send_reset_email(user.get_id(), user.email, user.name)

        logging.info('account: forgot password for user %s', user.email)

    @classmethod
    def _send_reset_email(cls, user_id, email, name):
        try:
            token = User.create_signup_token(user_id)
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        # generate the url that a user clicks to reset their password
        reset_url = uri_for(
            'reset_token',
            user_id=user_id,
            token=token,
            _full=True)

        logging.info('account: reset link for %s: %s', email, reset_url)

        try:
            EmailHelper.reset_email(email=email, name=name, url=reset_url)
        except Exception, e:
            raise InternalError('Unable to send reset password email: %s' % (e,))

    @classmethod
    def verify_reset(cls, user_id, token):
        if not all((user_id, token)):
            raise BadRequestError('Must supply user and token')
        try:
            user, _ = User.get_by_auth_token(
                int(user_id),
                token,
                'signup')
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        if not user or not user.active:
            raise NotFoundError('Could not find any user for "%s" and token "%s"' % (user_id, token))

        logging.info('account: reset verified: %s', user.email)

        return user

    @classmethod
    def reset_password(cls, user, token, password):
        if not all((token, password)):
            raise BadRequestError('Must supply token and password')
        try:
            user.set_password(password)
            user.put()
            # remove signup token, we don't want users to come back with an old link
            User.delete_signup_token(user.get_id(), token)
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        logging.info('account: reset password for user %s', user.email)

    @classmethod
    def deactivate(cls, user):
        try:
            user.active = False
            user.put()
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        logging.info('account: deactivate user %s', user.email)

    @classmethod
    def change_name(cls, user, name):
        try:
            orig_name = user.name
            user.name = name
            user.put()
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        logging.info('account: change name for %s from %s to %s', user.email, orig_name, name)

        return user

    @classmethod
    def change_email(cls, user, email, password):
        if not all((email, password)):
            raise BadRequestError('Must supply email and password')
        try:
            auth_user = User.get_by_auth_password(
                auth_id='auth:' + user.email,
                password=password)
            # return straight away if email is not changed
            if auth_user.email == email:
                return user

            uniques = [
                'User.auth_id:auth:' + email,
                'User.email:' + email]

            # test the uniqueness of the auth_id and email
            is_unique, _ = User.unique_model.create_multi(uniques)
            if not is_unique:
                raise DuplicateError('Email is already in use: %s' % (email,))

            # update storage with new email address
            user.auth_ids.append('auth:' + email)
            orig_email = user.email
            user.email = email
            user.verified = False
            user.put()

        except (InvalidAuthIdError, InvalidPasswordError):
            raise UnauthorizedError('Invalid email or password')
        except DuplicateError, e:
            raise
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        # generate signup token and send change email confirmation
        cls._send_verify_email(user.get_id(), email, user.name)

        logging.info('account: change email from %s to %s', orig_email, user.email)

        return user

    @classmethod
    def _send_change_email(cls, user_id, email, name):
        try:
            token = User.create_signup_token(user_id)
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        # generate the url that a user clicks to verify their email
        verify_url = uri_for(
            'verify_token',
            user_id=user_id,
            token=token,
            _full=True)

        logging.info('account: verify link for %s: %s', email, verify_url)

        try:
            EmailHelper.changed_email(email=email, name=name, url=verify_url)
        except Exception, e:
            raise InternalError('Unable to send verification email: %s' % (e,))

    @classmethod
    def change_password(cls, user, old_password, new_password):
        if not all((old_password, new_password)):
            raise BadRequestError('Must supply old and new passwords')
        try:
            User.get_by_auth_password(
                auth_id='auth:' + user.email,
                password=old_password)

            # update storage with new password
            user.set_password(new_password)
            user.put()

        except (InvalidAuthIdError, InvalidPasswordError):
            raise UnauthorizedError('Invalid email or password')
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        # generate signup token and send change password confirmation
        cls._send_password_email(user.get_id(), user.email, user.name)

        logging.info('account: change password for %s', user.email)

    @classmethod
    def _send_password_email(cls, user_id, email, name):
        try:
            token = User.create_signup_token(user_id)
        except Exception, e:
            raise InternalError('Internal storage failure: %s' % (e,))

        # generate the url that a user clicks to reset their password
        reset_url = uri_for(
            'reset_token',
            user_id=user_id,
            token=token,
            _full=True)

        logging.info('account: reset link for %s: %s', email, reset_url)

        try:
            EmailHelper.password_confirm(email=email, name=name, url=reset_url)
        except Exception, e:
            raise InternalError('Unable to send reset password email: %s' % (e,))

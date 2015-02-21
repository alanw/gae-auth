# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

import mock
import re

from webapp2_extras.auth import InvalidPasswordError

from handler_test import HanderTest
from models.user import User


class AccountTest(HanderTest):

    def register_user(self, email, name, verified=False):
        signup_data = {
            'email': email,
            'name': name,
            'password': 'test123'}
        response = self.send_request(
            path='/signup',
            post=signup_data)
        self.assertEqual(response.status_code, 201)
        user = User.get_by_auth_id('auth:' + signup_data['email'])
        if verified:
            user.verified = True
            user.put()
        return user


class SignupTest(AccountTest):

    def test_signup_success(self):
        signup_data = {
            'email': 'test@test.com',
            'name': 'test123',
            'password': 'test123'}
        response = self.send_request(
            path='/signup',
            post=signup_data)
        self.assertEqual(response.status_code, 201)
        user = User.get_by_auth_id('auth:' + signup_data.get('email'))
        self.assertEqual(user.email, signup_data.get('email'))
        self.assertEqual(user.name, signup_data.get('name'))
        self.assertTrue('$sha' in user.password)
        self.assertTrue(user.active)
        self.assertFalse(user.verified)

    def test_signup_post_missing_fields(self):
        signup_data = {
            'email': '',
            'name': ''}
        response = self.send_request(
            path='/signup',
            post=signup_data)
        self.assertEqual(response.status_code, 400)

    def test_signup_post_missing_bad_password(self):
        signup_data = {
            'email': 'bad',
            'name': 'test123',
            'password': ''}
        response = self.send_request(
            path='/signup',
            post=signup_data)
        self.assertEqual(response.status_code, 400)

    def test_email_in_use(self):
        self.register_user(email='test@test.com', name='test123')
        signup_data = {
            'email': 'test@test.com',  # duplicate
            'name': 'duplicate123',
            'password': 'test123'}
        response = self.send_request(
            path='/signup',
            post=signup_data)
        self.assertEqual(response.status_code, 409)

    def test_signup_verify_email_success(self):
        self.register_user(email='test@test.com', name='test123')
        messages = self.mail_stub.get_sent_messages(to='test@test.com')
        self.assertEqual(len(messages), 1)
        self.assertTrue('verify' in messages[0].subject)

    @mock.patch('google.appengine.api.mail.EmailMessage.send',
                mock.Mock(side_effect=Exception('BOOM')))
    def test_signup_verify_email_failure(self):
        signup_data = {
            'email': 'test@test.com',
            'name': 'test123',
            'password': 'test123'}
        response = self.send_request(
            path='/signup',
            post=signup_data)
        self.assertEqual(response.status_code, 503)
        messages = self.mail_stub.get_sent_messages(to='test@test.com')
        self.assertEqual(len(messages), 0)

    def test_signup_verify_email_complete(self):
        self.register_user(email='test@test.com', name='test123')
        message = self.mail_stub.get_sent_messages(to='test@test.com')[0]
        self.assertTrue('test123' in message.body.payload)


class VerifyTest(AccountTest):

    def test_verify_bad_user(self):
        response = self.send_request(path='/verify/1234/5EYJihivWyepLt9i1xt8f7')
        self.assertEqual(response.status_code, 404)

    def test_verify_bad_token(self):
        user = self.register_user(email='test@test.com', name='test123')
        response = self.send_request(path='/verify/' + str(user.get_id()) + '/bad')
        self.assertEqual(response.status_code, 404)

    def get_verify_token_from_email(self, email):
        message = self.mail_stub.get_sent_messages(to=email)[0]
        payload = message.body.payload
        return re.findall(r'http://.*verify/.*/(.*)', payload)[0]

    def test_verify_email_reuse_token(self):
        user = self.register_user(email='test@test.com', name='test123')
        token = self.get_verify_token_from_email(email='test@test.com')
        path = '/verify/' + str(user.get_id()) + '/' + token
        response = self.send_request(path=path)
        self.assertEqual(response.status_code, 200)
        response = self.send_request(path=path)
        self.assertEqual(response.status_code, 404)

    @mock.patch('models.user.User.get_by_auth_token',
                mock.Mock(side_effect=Exception('BOOM')))
    def test_verify_storage_failure(self):
        user = self.register_user(email='test@test.com', name='test123')
        token = self.get_verify_token_from_email(email='test@test.com')
        path = '/verify/' + str(user.get_id()) + '/' + token
        response = self.send_request(path=path)
        self.assertEqual(response.status_code, 503)


class LoginTest(AccountTest):

    def test_login_success(self):
        self.register_user(email='test@test.com', name='test123', verified=True)
        login_data = {
            'email': 'test@test.com',
            'password': 'test123'}
        response = self.send_request(
            path='/login',
            post=login_data)
        self.assertEqual(response.status_code, 200)

    def test_login_missing_email(self):
        login_data = {
            'email': '',
            'password': 'test123'}
        response = self.send_request(
            path='/login',
            post=login_data)
        self.assertEqual(response.status_code, 400)

    def test_login_email_not_exist(self):
        login_data = {
            'email': 'bad@bad.com',
            'password': 'test123'}
        response = self.send_request(
            path='/login',
            post=login_data)
        self.assertEqual(response.status_code, 401)

    @mock.patch('models.user.User.get_by_auth_password',
                mock.Mock(side_effect=Exception('BOOM')))
    def test_login_storage_failure(self):
        self.register_user(email='test@test.com', name='test123')
        login_data = {
            'email': 'test@test.com',
            'password': 'test123'}
        response = self.send_request(
            path='/login',
            post=login_data)
        self.assertEqual(response.status_code, 503)

    def test_login_session_cookie(self):
        self.register_user(email='test@test.com', name='test123')
        login_data = {
            'email': 'test@test.com',
            'password': 'test123'}
        response = self.send_request(
            path='/login',
            post=login_data)
        self.assertTrue('auth=' in response.headers.get('Set-Cookie'))
        self.assertTrue('Max-Age=' in response.headers.get('Set-Cookie'))

    def test_logout_session_cookie(self):
        self.register_user(email='test@test.com', name='test123')
        login_data = {
            'email': 'test@test.com',
            'password': 'test123'}
        self.send_request(path='/login', post=login_data)
        response = self.send_request(path='/logout')
        self.assertTrue('auth=' in response.headers.get('Set-Cookie'))
        self.assertTrue('Max-Age=' not in response.headers.get('Set-Cookie'))


class ResetPasswordTest(AccountTest):

    def test_forgot_password_success(self):
        self.register_user(email='test@test.com', name='test123')
        forgot_data = {
            'email': 'test@test.com'}
        response = self.send_request(
            path='/forgot',
            post=forgot_data)
        self.assertEqual(response.status_code, 200)

    def test_forgot_missing_email(self):
        self.register_user(email='test@test.com', name='test123')
        forgot_data = {
            'email': ''}
        response = self.send_request(
            path='/forgot',
            post=forgot_data)
        self.assertEqual(response.status_code, 400)

    def test_forgot_email_not_exist(self):
        self.register_user(email='test@test.com', name='test123')
        forgot_data = {
            'email': 'bad@bad.com'}
        response = self.send_request(
            path='/forgot',
            post=forgot_data)
        self.assertEqual(response.status_code, 401)

    def test_reset_bad_user(self):
        response = self.send_request(path='/reset/1234/5EYJihivWyepLt9i1xt8f7')
        self.assertEqual(response.status_code, 404)

    def test_reset_bad_token(self):
        user = self.register_user(email='test@test.com', name='test123')
        response = self.send_request(path='/reset/' + str(user.get_id()) + '/bad')
        self.assertEqual(response.status_code, 404)

    def get_reset_token_from_email(self, email):
        message = self.mail_stub.get_sent_messages(to=email)[1]
        payload = message.body.payload
        return re.findall(r'http://.*reset/.*/(.*)', payload)[0]

    def test_reset_password_success(self):
        user = self.register_user(email='test@test.com', name='test123')
        forgot_data = {
            'email': 'test@test.com'}
        self.send_request(path='/forgot', post=forgot_data)
        token = self.get_reset_token_from_email(email='test@test.com')
        path = '/reset/' + str(user.get_id()) + '/' + token
        response = self.send_request(path=path)
        self.assertEqual(response.status_code, 200)
        reset_data = {
            'email': 'test@test.com',
            'password': 'test123',
            'token': token}
        response = self.send_request(
            path='/reset',
            post=reset_data)
        self.assertEqual(response.status_code, 200)

    def test_reset_password_missing_password(self):
        user = self.register_user(email='test@test.com', name='test123')
        forgot_data = {
            'email': 'test@test.com'}
        self.send_request(path='/forgot', post=forgot_data)
        token = self.get_reset_token_from_email(email='test@test.com')
        path = '/reset/' + str(user.get_id()) + '/' + token
        response = self.send_request(path=path)
        self.assertEqual(response.status_code, 200)
        reset_data = {
            'email': 'test@test.com',
            'password': '',
            'token': token}
        response = self.send_request(
            path='/reset',
            post=reset_data)
        self.assertEqual(response.status_code, 400)

    def test_reset_password_reuse_token(self):
        user = self.register_user(email='test@test.com', name='test123')
        forgot_data = {
            'email': 'test@test.com'}
        self.send_request(path='/forgot', post=forgot_data)
        token = self.get_reset_token_from_email(email='test@test.com')
        path = '/reset/' + str(user.get_id()) + '/' + token
        response = self.send_request(path=path)
        self.assertEqual(response.status_code, 200)
        reset_data = {
            'email': 'test@test.com',
            'password': 'test123',
            'token': token}
        response = self.send_request(
            path='/reset',
            post=reset_data)
        self.assertEqual(response.status_code, 200)
        response = self.send_request(path=path)
        self.assertEqual(response.status_code, 404)

    def test_reset_password_then_login(self):
        user = self.register_user(email='test@test.com', name='test123')
        forgot_data = {
            'email': 'test@test.com'}
        self.send_request(path='/forgot', post=forgot_data)
        token = self.get_reset_token_from_email(email='test@test.com')
        path = '/reset/' + str(user.get_id()) + '/' + token
        response = self.send_request(path=path)
        self.assertEqual(response.status_code, 200)
        reset_data = {
            'email': 'test@test.com',
            'password': 'newpassword',
            'token': token}
        response = self.send_request(
            path='/reset',
            post=reset_data)
        self.assertEqual(response.status_code, 200)
        login_data = {
            'email': 'test@test.com',
            'password': 'newpassword'}
        response = self.send_request(
            path='/login',
            post=login_data)
        self.assertEqual(response.status_code, 200)


class AccountTest(AccountTest):

    def test_deactivate_success(self):
        user = self.register_user(email='test@test.com', name='test123')
        response = self.send_request(
            path='/account/' + str(user.get_id()) + '/deactivate',
            post={})
        self.assertEqual(response.status_code, 200)
        user = User.get_by_auth_id('auth:test@test.com')
        self.assertEqual(user.email, 'test@test.com')
        self.assertFalse(user.active)

    def test_signup_after_deactivate(self):
        user = self.register_user(email='test@test.com', name='test123', verified=True)
        response = self.send_request(
            path='/account/' + str(user.get_id()) + '/deactivate',
            post={})
        self.assertEqual(response.status_code, 200)
        signup_data = {
            'email': 'test@test.com',
            'name': 'test123',
            'password': 'test123'}
        response = self.send_request(
            path='/signup',
            post=signup_data)
        self.assertEqual(response.status_code, 201)
        user = User.get_by_auth_id('auth:test@test.com')
        self.assertTrue(user.active)
        self.assertFalse(user.verified)

    def test_change_name_success(self):
        user = self.register_user(email='test@test.com', name='test123')
        name_data = {'name': 'new123'}
        response = self.send_request(
            path='/account/' + str(user.get_id()) + '/name',
            post=name_data)
        self.assertEqual(response.status_code, 200)
        user = User.get_by_auth_id('auth:test@test.com')
        self.assertEqual(user.name, 'new123')

    def test_change_email_success(self):
        user = self.register_user(email='test@test.com', name='test123')
        email_data = {
            'email': 'new@new.com',
            'password': 'test123'}
        response = self.send_request(
            path='/account/' + str(user.get_id()) + '/email',
            post=email_data)
        self.assertEqual(response.status_code, 200)
        user = User.get_by_auth_id('auth:new@new.com')
        self.assertEqual(user.email, 'new@new.com')

    def test_change_email_bad_password(self):
        user = self.register_user(email='test@test.com', name='test123')
        email_data = {
            'email': 'new@new.com',
            'password': 'bad'}
        response = self.send_request(
            path='/account/' + str(user.get_id()) + '/email',
            post=email_data)
        self.assertEqual(response.status_code, 401)
        user = User.get_by_auth_id('auth:test@test.com')
        self.assertEqual(user.email, 'test@test.com')

    def test_change_email_in_use(self):
        self.register_user(email='first@first.com', name='test1')
        second_user = self.register_user(email='second@second.com', name='test2')
        email_data = {
            'email': 'first@first.com',
            'password': 'test123'}
        response = self.send_request(
            path='/account/' + str(second_user.get_id()) + '/email',
            post=email_data)
        self.assertEqual(response.status_code, 409)
        user = User.get_by_auth_id('auth:second@second.com')
        self.assertEqual(user.email, 'second@second.com')

    def test_change_password_success(self):
        user = self.register_user(email='test@test.com', name='test123')
        password_data = {
            'old_password': 'test123',
            'new_password': 'new123'}
        response = self.send_request(
            path='/account/' + str(user.get_id()) + '/password',
            post=password_data)
        self.assertEqual(response.status_code, 200)
        self.assertRaises(
            InvalidPasswordError,
            User.get_by_auth_password,
            auth_id='auth:test@test.com',
            password=password_data.get('old_password'))
        User.get_by_auth_password(
            auth_id='auth:test@test.com',
            password=password_data.get('new_password'))

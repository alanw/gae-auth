# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

from unittest import TestCase

from webapp2 import Request
from google.appengine.ext import testbed

import main
from handlers.base import BaseHandler


class HanderTest(TestCase):

    def setUp(self):
        super(HanderTest, self).setUp()
        BaseHandler._render_hook = self._mock_render
        self.cookies = None
        self.context = None
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()
        self.testbed.init_mail_stub()
        self.testbed.init_user_stub()
        self.mail_stub = self.testbed.get_stub(testbed.MAIL_SERVICE_NAME)
        main.app.config['csrf']['enabled'] = False

    def tearDown(self):
        self.testbed.deactivate()

    def _mock_render(self, response, template, **context):
        self.context = context

    def send_request(self, path, headers=None, post=None, method=None, json_body=None):
        headers = headers or {}
        if self.cookies is not None:
            headers.update({'Cookie': self.cookies})
        request = Request.blank(
            path=path,
            headers=headers,
            POST=post)
        if method:
            request.method = method
        if json_body:
            request.json_body = json_body
        response = request.get_response(main.app)
        self.cookies = response.headers.get('Set-Cookie')
        response.context = self.context
        return response

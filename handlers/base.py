# -*- coding: utf-8 -*-
# Copyright (c) 2015 Alan Wright. All rights reserved.

from webapp2 import RequestHandler, uri_for, cached_property, get_app
from webapp2_extras import auth, sessions, jinja2


def user_required(handler):
    """
    Decorator that checks if there's a user associated with the current
    session.

    Will also fail if there's no session present.
    """
    def check_login(self, *args, **kwargs):
        auth = self.auth
        # todo: add support for redirecting to where
        # they came from (otherwise redirect to 'home')
        if not auth.get_user_by_session():
            self.redirect_to('login', _abort=True)
        else:
            return handler(self, *args, **kwargs)
    return check_login


def jinja2_factory(app):
    """
    Method for attaching additional globals/filters to jinja
    """
    jinja = jinja2.Jinja2(app)
    jinja.environment.globals['uri_for'] = uri_for
    jinja.environment.trim_blocks = True
    jinja.environment.lstrip_blocks = True
    return jinja


class BaseHandler(RequestHandler):

    @cached_property
    def auth(self):
        """
        Shortcut to access the auth instance as a property.
        """
        return auth.get_auth()

    @cached_property
    def user_info(self):
        """
        Shortcut to access a subset of the user attributes that are stored
        in the session.

        The list of attributes to store in the session is specified in
            config['webapp2_extras.auth']['user_attributes'].
        :returns
            A dictionary with most user information
        """
        return self.auth.get_user_by_session()

    @cached_property
    def user(self):
        """
        Shortcut to access the current logged in user.

        Unlike user_info, it fetches information from the persistence layer and
        returns an instance of the underlying model.

        :returns
            The instance of the user model associated to the logged in user.
        """
        user = self.user_info
        return self.user_model.get_by_id(user['user_id']) if user else None

    @cached_property
    def user_id(self):
        """
        Shortcut to access the current logged in user id.
        """
        return int(self.user.key.id()) if self.user else None

    @cached_property
    def user_model(self):
        """
        Returns the implementation of the user model.

        It is consistent with config['webapp2_extras.auth']['user_model'], if set.
        """
        return self.auth.store.user_model

    @cached_property
    def session(self):
        """
        Shortcut to access the current session.
        """
        return self.session_store.get_session(backend='datastore')

    @cached_property
    def country(self):
        """
        Returns the source country of the request, or US is not available.
        """
        return self.request.headers.get('X-AppEngine-Country') or 'US'

    @cached_property
    def jinja2(self):
        return jinja2.get_jinja2(factory=jinja2_factory, app=self.app)

    def render_template(self, template, **context):
        ctx = {
            'debug': get_app().config.get('debug'),
            'path': self.request.path,
            'user': self.user_info}
        ctx.update(context)
        self._render_hook(self.response, template, **ctx)
        self.response.write(self.jinja2.render_template(template, **ctx))

    def _render_hook(self, response, template, **context):
        pass  # used for unit testing

    def initialize(self, request, response):
        super(BaseHandler, self).initialize(request, response)
        if self.request.host.endswith('gae-user-profiles.appspot.com'):
            self.request.host = 'eternitysea.com'
            self.redirect(self.request.url, permanent=True)

    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)
        try:
            super(BaseHandler, self).dispatch()
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

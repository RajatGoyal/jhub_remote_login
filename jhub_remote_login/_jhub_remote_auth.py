from traitlets import Bool, List
from tornado import gen, web
from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
import string
import random
import functools
# import uuid
# import re
# from base64 import b32encode, b32decode
'''
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import List
'''
# from traitlets import Unicode
# from ast import literal_eval


class RemoteUserLoginHandler(BaseHandler):
    """
    Handler for /login
    Creates a new user with a random UUID, and auto starts their server
    """

    def initialize(self, force_new_server, process_user):
        super().initialize()
        self.force_new_server = force_new_server
        self.process_user = process_user

    def get_username(self):
        username = self.get_argument('user', None, True)
        if username != "" and username is not None:
            return username
        else:
            raise web.HTTPError(401,
                                "You are not Authenticated to do this (1)")

    def check_header(self, key, value):
        self.log.info(f"headers -> {self.request.headers}")
        header_value = self.request.headers.get(key, "")
        if value == header_value:
            return True
        else:
            return False

    def get_tmp_cookie(self, key, value):
        self.log.info(f"cookie -> {self.get_cookie(key)}")
        if self.get_cookie(key):
            return True
        else:
            if self.check_header(key, value):
                self._set_cookie(key, value)
                return True
            else:
                return False

    def clear_tmp_cookie(self, key):
        self.log.info(f"cookie -> {self.get_cookie(key)}")
        if self.get_cookie(key):
            self.clear_cookie(key)
            return True
        else:
            return False

    @gen.coroutine
    async def get(self):

        raw_user = self.get_current_user()

        if raw_user:
            if self.force_new_server and raw_user.running:
                # Stop the user's current terminal instance if it is
                # running so that they get a new one. Should hopefully
                # only end up here if have hit the /restart URL path.

                status = yield raw_user.spawner.poll_and_notify()
                if status is None:
                    yield self.stop_single_user(raw_user)

                # Also force a new user name be generated so don't have
                # issues with browser caching web pages for anything
                # want to be able to change for a demo. Only way to do
                # this seems to be to clear the login cookie and force a
                # redirect back to the top of the site, hoping we do not
                # get into a loop.

                self.clear_login_cookie()
                self.redirect('/')

        else:
            if self.get_tmp_cookie('validation', 'ok'):
                username = self.get_username()
                if username is not None and username != "":
                    if (await gen.maybe_future(self.authenticator.check_whitelist(username))):
                        raw_user = self.user_from_username(username)
                        self.set_login_cookie(raw_user)
                        self.clear_tmp_cookie('validation')
                    else:
                        raise web.HTTPError(401,
                                            "You are not Authenticated to do this (4)")
                else:
                    raise web.HTTPError(401,
                                        "You are not Authenticated to do this (2)")
            else:
                raise web.HTTPError(401,
                                    "You are not Authenticated to do this (3)")

        if raw_user:
            user = yield gen.maybe_future(self.process_user(raw_user, self))

        self.redirect(self.get_argument("next", user.url))


class RemoteUserAuthenticator(Authenticator):
    """
    JupyterHub Authenticator for use with tmpnb.org
    When JupyterHub is configured to use this authenticator, visiting the home
    page immediately logs the user in with a randomly generated UUID if they
    are already not logged in, and spawns a server for them.
    """

    auto_login = True
    login_service = 'remotelogin'

    force_new_server = Bool(
        False,
        help="""
        Stop the user's server and start a new one when visiting /hub/login
        When set to True, users going to /hub/login will *always* get a
        new single-user server. When set to False, they'll be
        redirected to their current session if one exists.
        """,
        config=True
    )

    def process_user(self, user, handler):
        return user

    def get_handlers(self, app):
        extra_settings = {
            'force_new_server': self.force_new_server,
            'process_user': self.process_user
        }
        return [
            ('/login', RemoteUserLoginHandler, extra_settings)
        ]

    def login_url(self, base_url):
        return url_path_join(base_url, 'login')

# def login_url(self, base_url):
#    return url_path_join(base_url, 'remotelogin')

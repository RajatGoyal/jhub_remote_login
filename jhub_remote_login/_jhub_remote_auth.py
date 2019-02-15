from traitlets import Bool, Unicode
from tornado import gen, web
from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
# from encryption import RSATools
# import base64


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
        '''
        username_encr = self.get_argument('user', None, True)
        username = self.decrypt_content(username_encr)
        if username != "" and username is not None:
            return username
        else:
            raise web.HTTPError(401,
                                "You are not Authenticated to do this (1)")
        '''
        username = self.get_argument('user', None, True)
        if username != "" and username is not None:
            return username
        else:
            raise web.HTTPError(401,
                                "You are not Authenticated to do this (1)")

    def check_header(self, key, value):
        header_value = self.request.headers.get(key, "")
        '''
        self.log.info(
            f"Trying to get the user for the token"
            f" {header_value}-> {self.user_for_token(header_value)}")
        '''
        if value == header_value:
            return True
        else:
            return False

    def get_tmp_cookie(self, key, value):
        '''
        if self.get_cookie(self.decrypt_content(key)):
            return True
        else:
            if self.check_header(key,
                                 self.decrypt_content(value)):
                self._set_cookie(self.encrypt_content(key),
                                 self.encrypt_content(value))
                return True
            else:
                return False
        '''
        if self.get_cookie(key):
            return True
        else:
            if self.check_header(key, value):
                self._set_cookie(key, value)
                return True
            else:
                return False

    def clear_tmp_cookie(self, key):
        if self.get_cookie(key):
            self.clear_cookie(key)
            return True
        else:
            return False
    '''
    def get_rsa_private_key(self, private_key_pem, private_key_password):
        private_key = RSATools().load_private_key_pem_variable(
            private_key_pem, private_key_password)
        return private_key

    def get_rsa_public_key(self, public_key_pem):
        public_key = RSATools().load_private_key_pem_variable(
            public_key_pem)
        return public_key

    def decrypt_content(self, content):
        if self.rsa_private_key_pem is not None and\
           self.rsa_private_key_pem != "":
            private_key = self.get_rsa_private_key(
                self.rsa_private_key_pem,
                self.rsa_private_key_password
            )
            # We assume that the encrypted content
            # comes encoded in base64
            decrypted_content = RSATools().decrypt_text_rsa(
                base64.b64decode(content), private_key)
            return decrypted_content
        else:
            return content

    def encrypt_content(self, content):
        if self.rsa_public_key_pem is not None and\
           self.rsa_public_key_pem != "":
            public_key = self.get_rsa_public_key(
                self.rsa_public_key_pem)

            encrypted_content = RSATools().encrypt_text_rsa(
                content, public_key)
            # We encode the encrypted content in base64
            encrypted_content_b64 = base64.b64encode(encrypted_content)
            return encrypted_content_b64
        else:
            return content
    '''
    @gen.coroutine
    def get(self):

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
                return self.redirect('/')

        else:
            if self.get_tmp_cookie(self.authenticator.tmp_auth_key,
                                   self.authenticator.tmp_auth_value):
                username = self.get_username()
                if username is not None and username != "":
                    whitelist = self.authenticator.whitelist
                    if whitelist and username in whitelist:
                        raw_user = self.user_from_username(username)
                        self.clear_tmp_cookie(self.authenticator.tmp_auth_key)
                        self.set_login_cookie(raw_user)
                    else:
                        raise web.HTTPError(401,
                                            "You are not Authenticated "
                                            "to do this (4)")
                else:
                    raise web.HTTPError(401,
                                        "You are not Authenticated to do "
                                        "this (2)")
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
        default_value=False,
        help="""
        Stop the user's server and start a new one when visiting /hub/login
        When set to True, users going to /hub/login will *always* get a
        new single-user server. When set to False, they'll be
        redirected to their current session if one exists.
        """,
        config=True
    )

    tmp_auth_key = Unicode(
        default_value="Validation",
        help="""
        The name of the temp header/cookie set to help in log in tasks
        """,
        config=True
    )

    tmp_auth_value = Unicode(
        default_value="ok",
        help="""
        The value that should contain the temp
        header/cookie set to help in log in tasks
        """,
        config=True
    )

    rsa_private_key_pem = Unicode(
        default_value="",
        help="""
        String containing the PEM of the private key to use with RSA
        encryption/decryption.
        """,
        config=True
    )

    rsa_public_key_pem = Unicode(
        default_value="",
        help="""
        String containing the PEM of the public key to use with RSA
        encryption/decryption.
        """,
        config=True
    )

    rsa_private_key_password = Unicode(
        default_value="",
        help="""
        String containing the password to load the PEM variable
        of the private key to use with RSA encryption/decryption.
        """,
        config=True
    )

    def process_user(self, user, handler):
        return user

    def get_handlers(self, app):
        extra_settings = {
            'force_new_server': self.force_new_server,
            'process_user': self.process_user,
        }

        return [
            ('/login', RemoteUserLoginHandler, extra_settings)
        ]

    def login_url(self, base_url):
        return url_path_join(base_url, 'login')

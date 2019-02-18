from traitlets import Bool, Unicode
from tornado import gen, web
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from jupyterhub.services.auth import HubAuth
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64


class RSATools():
    def generate_rsa_keys(self, keysize=2048,
                          password=None,
                          store=False,
                          private_key_path="private_key.pem",
                          public_key_path="public_key.pem"):

        private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=default_backend()
                                               )

        if password is None:
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    password.encode("utf-8"))
            )
        if store:
            file_out = open(private_key_path, "wb")
            file_out.write(pem_private)

        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        if store:
            file_out = open(public_key_path, "wb")
            file_out.write(pem_public)

        return pem_private, pem_public

    def encrypt_text_rsa(self, plain_text, public_key):

        ciphertext = public_key.encrypt(plain_text.encode("utf-8"),
                                        padding.OAEP(
                                            mgf=padding.MGF1(
                                                algorithm=hashes.SHA256()
                                            ),
                                            algorithm=hashes.SHA256(),
                                            label=None
        )
        )
        return ciphertext

    def decrypt_text_rsa(self, ciphertext, private_key):
        plain_text = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plain_text.decode("utf-8")

    def load_private_key_pem_variable(self, private_key_pem, password=None):
        if password is not None:
            password = password.encode("utf-8")

        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
            backend=default_backend()
        )
        return private_key

    def load_public_key_pem_variable(self, public_key_pem):

        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        return public_key


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
        '''

    async def user_for_token(self, token):
        """Retrieve the user for a given token, via /hub/api/user"""
        req = HTTPRequest(
            url_path_join(self.base_url, "api/user"),
            headers={
                'Authorization': f'token {token}'
            },
        )
        response = await AsyncHTTPClient().fetch(req)
        return response

    async def match_token_username(self, token, username):

        user_retrieved = await self.user_for_token(token)
        if user_retrieved is not None:
            if username == user_retrieved['name']:
                return True
            else:
                return False
        else:
            return False

    def check_header_token(self, key, username):
        header_value = self.request.headers.get(key, "")

        if header_value is None or header_value == "":
            return False
        match = self.match_token_username(header_value, username)
        if match is True:
            return True
        else:
            return False

    def get_tmp_cookie(self, key, username):
        if self.get_cookie(self.decrypt_content(key)):
            return True
        else:
            if self.check_header_token(key,
                                       self.decrypt_content(username)):
                self._set_cookie(self.encrypt_content(key),
                                 self.encrypt_content(username))
                return True
            else:
                return False
        '''
        if self.get_cookie(key):
            return True
        else:
            if self.check_header_token(key, username):
                self._set_cookie(key, username)
                return True
            else:
                return False
        '''

    def clear_tmp_cookie(self, key):
        if self.get_cookie(key):
            self.clear_cookie(key)
            return True
        else:
            return False

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
            username = self.get_username()
            if self.get_tmp_cookie(self.authenticator.tmp_auth_key,
                                   username):
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

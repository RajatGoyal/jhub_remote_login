from traitlets import Bool, Unicode
from tornado import gen, web
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
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

    async def user_for_token(self, token):
        """Retrieve the user for a given token, via /hub/api/user"""
        url_api = url_path_join(self.authenticator.url_hub_api, "user")
        self.log.info(f"url  -> {url_api}")
        req = HTTPRequest(
            url_api,
            headers={
                'Authorization': f'token {token}'
            },
        )
        response = await AsyncHTTPClient().fetch(req)
        return response

    async def match_token_username(self, token, username):
        self.log.info(f"trying to get user_for_token")
        user_retrieved = await self.user_for_token(token)
        self.log.info(f"user_retrieved -> {user_retrieved}")
        if user_retrieved is not None:
            self.log.info(f"username -> {username}")
            self.log.info(f"user_retrieved -> {user_retrieved}")
            if username == user_retrieved['name']:
                return True
            else:
                return False
        else:
            return False

    def check_username_whitelist(self, username):
        whitelist = self.authenticator.whitelist
        if whitelist and username in whitelist:
            self.log.info("Username in whitelist")
            return True
        else:
            return False

    async def validate_user_token(self, token, username):
        check_whitelist = self.check_username_whitelist(username)
        check_token_user = await self.match_token_username(token, username)

        if check_whitelist is False:
            self.log.info("Username NOT in whitelist")
            return False
        if check_token_user is False:
            self.log.info("NO Match between token & username")
            return False

        if check_whitelist is True and check_token_user is True:
            return True

        return False

    def get_header(self, key):
        header_value = self.request.headers.get(key, "")
        if header_value is None or header_value == "":
            return None
        else:
            return header_value

    def get_tmp_cookie(self, key):
        cookie_content = self.get_cookie(key)
        if cookie_content is None or cookie_content == "":
            return None
        else:
            return cookie_content

    def clear_tmp_cookie(self, key):
        if self.get_cookie(key):
            self.clear_cookie(key)
            return True
        else:
            return False

    def get_rsa_private_key(self, private_key_pem, private_key_password):
        private_key = RSATools().load_private_key_pem_variable(
            private_key_pem.encode('utf-8'), private_key_password)
        return private_key

    def get_rsa_public_key(self, public_key_pem):
        public_key = RSATools().load_private_key_pem_variable(
            public_key_pem.encode('utf-8'))
        return public_key

    def decrypt_content(self, content):
        if self.authenticator.rsa_private_key_pem is not None and\
           self.authenticator.rsa_private_key_pem != "":
            private_key = self.get_rsa_private_key(
                self.authenticator.rsa_private_key_pem,
                self.authenticator.rsa_private_key_password
            )
            # We assume that the encrypted content
            # comes encoded in base64
            decrypted_content = RSATools().decrypt_text_rsa(
                base64.b64decode(content), private_key)
            return decrypted_content
        else:
            return content

    def encrypt_content(self, content):
        if self.authenticator.rsa_public_key_pem is not None and\
           self.authenticator.rsa_public_key_pem != "":
            public_key = self.get_rsa_public_key(
                self.authenticator.rsa_public_key_pem)

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
            # Check if the cookie which contains the username exists
            self.log.info(
                "Check if the cookie which contains the username exists")
            username = self.get_tmp_cookie(self.authenticator.header_user_key)
            if username is None:
                # If no cookie, check if the header with the username exists
                self.log.info(
                    "If no cookie, "
                    "check if the header with the username exists")
                username = self.get_header(self.authenticator.header_user_key)
                if username is None:
                    raise web.HTTPError(
                        401,
                        "You are not Authenticated to do this (1)")

            # Check if the cookie which contains the token exists
            self.log.info(
                "Check if the cookie which contains the token exists")
            token = self.get_tmp_cookie(self.authenticator.header_token_key)
            if token is None:
                self.log.info(
                    "If no cookie, check if the header with the token exists")
                # If no cookie, check if the header with the token exists
                token = self.get_header(self.authenticator.header_token_key)
                if token is None:
                    raise web.HTTPError(
                        401,
                        "You are not Authenticated to do this (2)")

            if username is not None and username != "" and\
                    token is not None and token != "":

                self.log.info(
                    f"Encryption is '{self.authenticator.use_encryption}'")

                # Set a temp cookie with the username received
                self._set_cookie(self.authenticator.header_user_key,
                                 username)
                # Decrypt the username if the use_encryption variable is True
                if self.authenticator.use_encryption is True:
                    username = self.decrypt_content(username)

                # Set a temp cookie with the token received
                self._set_cookie(self.authenticator.header_token_key,
                                 token)
                # Decrypt the token if the use_encryption variable is True
                if self.authenticator.use_encryption is True:
                    token = self.decrypt_content(token)
                user_validated = yield gen.maybe_future(self.validate_user_token(token, username))
                if user_validated is True:
                    self.log.info("Match between token & username")
                    raw_user = self.user_from_username(username)
                    self.clear_tmp_cookie(
                        self.authenticator.header_user_key)
                    self.clear_tmp_cookie(
                        self.authenticator.header_token_key)
                    self.set_login_cookie(raw_user)
                else:
                    # self.clear_tmp_cookie(
                    #    self.authenticator.header_user_key)
                    # self.clear_tmp_cookie(
                    #    self.authenticator.header_token_key)
                    return web.HTTPError(
                        401,
                        "You are not Authenticated to do this (3)")
            else:
                raise web.HTTPError(401,
                                    "You are not Authenticated to do this (4)")
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

    header_user_key = Unicode(
        default_value="username",
        help="""
        The name of the temp header/cookie set to save the username
        that helps in the log in tasks
        """,
        config=True
    )

    header_token_key = Unicode(
        default_value="token",
        help="""
        The name of the temp header/cookie set to save the token
        that helps in the log in tasks
        """,
        config=True
    )

    url_hub_api = Unicode(
        default_value="/hub/api/",
        help="""
        The URL to use when requesting endpoints from the Hub API
        """,
        config=True
    )

    use_encryption = Bool(
        default_value=False,
        help="""
        Set to True if you are going to use the
        token and username headers encrypted.
        False if not
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

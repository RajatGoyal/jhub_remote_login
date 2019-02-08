# import re
# from base64 import b32encode, b32decode
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import List
# from traitlets import Unicode
# from ast import literal_eval

'''
def safeinput_encode(input_str):
    """
    :param input_str: string
    :return: b32encoded utf-8 string with stripped padding equals
    """
    encoded_str = str(b32encode(bytes(input_str, 'utf-8')), 'utf-8')
    return encoded_str.replace('=', '')


def safeinput_decode(input_str):
    """
    :param input_str: expects a b32encoded utf-8 string
    :return: a decoded utf-8 string
    """
    # Encoder removed "=" padding to satisfy validate_input
    # Pad with "="" according to:
    # https://tools.ietf.org/html/rfc3548 :
    # (1) the final quantum of encoding input is an integral multiple of 40
    # bits; here, the final unit of encoded output will be an integral
    # multiple of 8 characters with no "=" padding.
    if len(input_str) % 8 != 0:
        padlen = 8 - (len(input_str) % 8)
        padding = "".join('=' for i in range(padlen))
        decode_str = "{}{}".format(input_str, padding)
    else:
        decode_str = input_str

    return str(b32decode(bytes(decode_str, 'utf-8')), 'utf-8')
'''


def extract_headers(request, headers):
    user_data = {}
    for _, header in enumerate(headers):
        value = request.headers.get(header, "")
        if value:
            try:
                user_data[header] = value
            except KeyError:
                pass
    return user_data


'''
class PartialBaseURLHandler(BaseHandler):
    """
    Fix against /base_url requests are not redirected to /base_url/home
    """
    @web.authenticated
    @gen.coroutine
    def get(self):
        self.redirect(url_path_join(self.hub.server.base_url, 'home'))
'''


class RemoteUserLogoutHandler(BaseHandler):

    @gen.coroutine
    def get(self):
        user = self.get_current_user()
        if user:
            self.clear_login_cookie()
        self.redirect(self.hub.server.base_url)


class RemoteUserLoginHandler(BaseHandler):

    @gen.coroutine
    def prepare(self):
        """ login user """
        if self.get_current_user() is not None:
            self.log.info(
                f"User: {self.get_current_user()}:"
                f"{self.get_current_user().name} is already authenticated")
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            user_auth = extract_headers(self.request,
                                        self.authenticator.header_names)
            self.log.info(
                f"self.authenticator.header_name -> "
                f"{self.authenticator.header_names}")
            self.log.info(f"user_data -> {user_auth}")
            self.log.info(f"self.request -> {self.request}")
            self.log.info(f"self.request.headers -> {self.request.headers}")

            for item in self.authenticator.header_names:
                if item not in user_auth:
                    raise web.HTTPError(401,
                                        "You are not Authenticated to do this")
            yield self.login_user(user_auth)

            argument = self.get_argument("next", None, True)
            if argument is not None:
                self.redirect(argument)
            else:
                self.redirect(url_path_join(self.hub.server.base_url, 'home'))


class RemoteUserAuthenticator(Authenticator):
    """
    Accept the authenticated user name from the Remote-User HTTP header.
    """
    header_names = List(
        default_value=['Remote-User', 'Encr-Key'],
        config=True,
        help="""HTTP headers to inspect for the username and encryption key"""
    )

    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
            (r'/logout', RemoteUserLogoutHandler)
        ]

    '''
    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()
    '''
    @gen.coroutine
    def authenticate(self, handler, data):
        for item in self.authenticator.header_names:
            if item not in data:
                self.log.info(f"A '{item}' header is required"
                              f" for authentication")
                return None


class RemoteUserLocalAuthenticator(LocalAuthenticator):
    """
    Accept the authenticated user name from the Remote-User HTTP header.
    Derived from LocalAuthenticator for use of features such as adding
    local accounts through the admin interface.
    """
    header_names = List(
        default_value=['Remote-User', 'Encr-Key'],
        config=True,
        help="""HTTP headers to inspect for the username and encryption key"""
    )

    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
            (r'/logout', RemoteUserLogoutHandler)
        ]

    '''
    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()
    '''
    @gen.coroutine
    def authenticate(self, handler, data):
        for item in self.authenticator.header_names:
            if item not in data:
                self.log.info(f"A '{item}' header is required"
                              f" for authentication")
                return None


'''
class DataRemoteUserAuthenticator(RemoteUserAuthenticator):
    """
    An Authenticator that supports dynamic header information
    """

    auth_headers = List(
        default_value=['Remote-User'],
        config=True,
        help="""List of allowed HTTP headers to get from user data"""
    )

    data_headers = List(
        default_value=[],
        config=True,
        help="""List of allowed data headers"""
    )

    # These paths are an extension of the prefix base url e.g. /dag/hub
    def get_handlers(self, app):
        return [
            (r'/login', RemoteUserLoginHandler),
            (r'/logout', RemoteUserLogoutHandler),
            (r'/data', DataHandler),
        ]

    @gen.coroutine
    def authenticate(self, handler, data):
        if 'Remote-User' not in data:
            self.log.info("A Remote-User header is required")
            return None

        # Login
        real_name = data['Remote-User'].lower()
        # Make it alphanumeric
        pattern = re.compile(r'[\W_]+', re.UNICODE)
        real_name = pattern.sub('', real_name)
        encoded_name = safeinput_encode(real_name)

        user = {
            'name': encoded_name,
            'auth_state': {
                'real_name': real_name
            }
        }
        self.log.info("Authenticated: {} - Login".format(user))
        return user

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        """Pass upstream_token to spawner via environment variable"""
        auth_state = yield user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return

        if isinstance(auth_state, dict) and 'real_name' in auth_state:
            user.real_name = auth_state['real_name']
            self.log.debug("Pre-Spawn: {} set user real_name {}".format(
                user, user.real_name))
'''

.. image:: https://travis-ci.org/cbjuan/jhub_remote_login.svg?branch=master
    :target: https://travis-ci.org/cbjuan/jhub_remote_login

=========================
Jupyterhub Authenticators
=========================

Authenticate to Jupyterhub using an authenticating proxy that can set
the Remote-User header.
Also supports for passing additional information to the jupyter user. This includes a
list of user defined /data headers.

-----------------------------------------
Architecture and Security Recommendations
-----------------------------------------

This type of authentication relies on an HTTP header, and a malicious
client could spoof the REMOTE_USER header.  The recommended architecture for this
type of authentication requires that an authenticating proxy be placed in front
of your Jupyterhub.  Your Jupyerhub should **only** be accessible from the proxy
and **never** directly accessible by a client.  

This type of access is typically enforced with network access controls.  E.g. in
a simple case, the host on which the Jupyterhub service accepts incoming requests
has its host based firewall configured to only accept incoming connections from
the proxy host.

Further, the authenticating proxy should make sure it removes any REMOTE_USER
headers from incoming requests and only applies the header to proxied requests
that have been properly authenticated.

------------
Installation
------------

This package can be installed with `pip` either from a local git repository or from PyPi.

Installation from local git repository::

    cd jhub_remote_login
    pip install .

Installation from PyPi::

    pip install jhub-remote-login

Alternately, you can add the local project folder must be on your PYTHONPATH.

-------------
Configuration
-------------

You should edit your `jupyterhub_config.py` config file to set the
authenticator class::

    c.JupyterHub.authenticator_class = 'jhub_remote_login.RemoteUserAuthenticator'

You should be able to start jupyterhub.  The "/login" resource
will look for the authenticated user name in the HTTP header "Remote-User".
If found, and not blank, you will be logged in as that user.

Alternatively, you can use `RemoteUserLocalAuthenticator`::

    c.JupyterHub.authenticator_class = 'jhub_remote_login.RemoteUserLocalAuthenticator'

This provides the same authentication functionality but is derived from
`LocalAuthenticator` and therefore provides features such as the ability
to add local accounts through the admin interface if configured to do so.

--------------------
Dummy Authentication
--------------------

Provides an option for testing JupyterHub authentication with a dummy authenticator
that can have a global preset password for any account::

    c.JupyterHub.authenticator_class = 'jhub_remote_login.DummyAuthenticator'
    c.DummyAuthenticator.password = 'password'


Note! Don't use in production.

-------------------------------------------------------------
Remote User Authentication extended with user-defined headers
-------------------------------------------------------------

Provides the capability to supply the jupyterhub user with additional state information
via the /data path. This adds two base request paths to the jupyterhub web application::

'/login' -> requires a non empty Remote-User header
'/data' -> requires both an authenticated request and a valid configured header

Before information can be passed to the user via the '/data' path, a list of valid
headers is required. These preset valid headers are then upon a POST request to the
'/data' URl appended to the current authenticated jupyterhub user data dictionary. I.e.
user.data[Header] = HeaderValue

The extended authenticator can be activated by setting the following option in the
jupyterhub config file::

    c.JupyterHub.authenticator_class = 'jhub_remote_login.DataRemoteUserAuthenticator'
    # Making 'State' a valid header to pass to /data
    c.DataRemoteUserAuthenticator.data_headers = ['State']

Beyond providing the custom header possibility, the authenticator also by default
encodes the Remote-User header with 'b32encode'. The authenticator therefore also provides
the possibility of storing the actual value for debugging purposes in the user.real_name
variable via the jupyterhub auth_state mechanism of passing information to
the spawner as noted at `Authenticators <https://jupyterhub.readthedocs
.io/en/stable/reference/authenticators.html>`_.
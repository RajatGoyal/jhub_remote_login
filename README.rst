=========================
Jupyterhub Authenticators
=========================


.. image:: https://travis-ci.org/cbjuan/jhub_remote_login.svg?branch=master
    :target: https://travis-ci.org/cbjuan/jhub_remote_login


Authenticate to Jupyterhub using an HTTP headers. 1 to pass the JupyterHub username and 
other to pass a valid JHub token for that user.

-----------------------------------------
Architecture and Security Recommendations
-----------------------------------------

This type of authentication relies on an HTTP headers, and a malicious
client could spoof the REMOTE_USER header.  

For that reason, we provide also asymmetric encryption capabilities (RSA-based)
to pass the username and token.

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

## Configuration

You should edit your `jupyterhub_config.py` (in the JupyterHub) config file to set the authenticator class and the proper config variables::

    hub:
        image:
            name: cbjuan/k8s-hub-remotelogin
            tag: v0.0.119
        extraConfig: |
            c.JupyterHub.authenticator_class = 'jhub_remote_login.RemoteUserAuthenticator'
            c.Authenticator.whitelist = {'cbjuan'}
            c.Authenticator.admin_users = {'cbjuan'}
            c.Authenticator.header_user_key = 'username'
            c.Authenticator.header_token_key = 'token'
            c.Authenticator.url_hub_api = 'https://ibm-q-jupyter-hub.us-south.containers.appdomain.cloud/hub/api'

            c.Authenticator.use_encryption = False
            c.Authenticator.rsa_private_key_pem = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIZgzl2iM/LbcCAggA\nMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBCq9uPHHV/11PcYdX/QpH2dBIIE\n0B1mPFLY9UdYx4eps1XoYnMecvTB+fUNeyA3FkAQfqOswbMAl2vjjiDSudF4gNps\ntXAzUV/OEKXqTN5SXYB/qbw3ePxink5NDduiS6Lu6VvEUa+wKw1vN9sF7HOkQbfq\nsl5z1pitdP1P5/F2yqeoWba38u0dZBVxnLFPv3vf/n26Cj7G3oQCrN/giS1Bnznq\n+TMRNap6UIBa4QF5AjmXsKJqSOA9rc/5rpUUR3hbKFahGIXfSIqFE5eB85Ar5s9s\nH/u2P+ESoZWobc6m51chYJtMqKAtCTUwxjhQuRg3JaDRF8vY4eQ/tXLe7LY6JPc5\nlME7pqRci9qVvuq0DDLUEZ1T5QKWl5SLr/701qNueVK8+Q7MyOjP1ym44Nzl6lV9\n3FvKmHNIuRFzMpceCp9eaUUuIb9D59/rtT/o1Pf5E/4NXEGB0NAhNhg7KalqVrCP\nD/vMfz2CHnc9UUBDUm7GE5VUAKARBBSzOBwhEuU3a5PTuX4PfxITXt4AsNfblK1O\nXZSVv/AIAS1oObdQRcWDtAUb4GJGmUQyOce/lM/JLWmZZEVD3ZxyPVraij3tIDJ/\nAlzgIAnf/SXp3IA7+qvgfABsGfS00XRoKhoJVvVp23ruqUbGbkJMLozMh+q0Tj3X\ncI4IgZjAoxg63WlUTOBJ16p55VtPCVZJ/YEATkej4gKQy+OvtTozDDZ995G8nf7t\n5ebvhlRTSp3mquR64sQX6Qjh5s0gZ4fFCgCXPgU0e3qc6l0t2hxZ7hdpGHzMbZZO\nHLcgrutcBIlT2vFkN9yyvHM8ed/dUVKQAg9pEk0bJuiFDn+sHB69RIRwrgd07FT/\nYmrSE79BJEwjGBT/hjsZcIkVkkORSsuQmU/flGGZ86UajBhFm2Bhjx8UGC8u9e/B\n/T/ZPFYFldbSZPJLEwoCXLGZXnIEEyNnrYiIo29rhrj8XQVp5RnvRsCHI6on4TE3\nw8du3hnOHdbcqBLvIQ+AR73w0kn47nbKVOOFULlduQjAgrL0sI0jTOJ2AnuKp74S\nKjmWhTukSIjMSYQD7S9Ps40/hcMP+FzC4C29AMMAwuRNy0ymhd+3I2aMI1znlIfS\n6Stmuvdfyn8FCqIkY75fhmOyMpP6yOCGKMrKuWdFC+3WtxrY7peVBanXh+ONjyED\n8D1LQOyNKYha3EmsNeKz3jgvVbUnJ3udDistmpqG8yfOZ7yTRSzror2tvbC/ff17\nUdMx22y9S+xZW58vrHKqy9Am665Mi7OSLWgNLY3N/uG66iFvu+loIQOT5cFprOKP\nZmb7ijHOxOXmwPh7G6CdkAYvmLIZoC9sfPYRypQxhx+OMc3fx/9loq6gDb67/Pty\nGRJFkC4KcwhkcSX0IfL2AXKBsMBct93asaTsGmHKBFzOSSZ70+WQvtIIrrslI2Yt\n5ZWeIkkjvbg0JC1Io1fuMtFzVMB+oIvhMEcErOHtktYNd1eWhkfBv/jswAdikyAq\nDEpVdGBx/SdBKBD4RAGJNU3ogD0RKDQk808EPcSsRLT+px47J/K7I/wBGrdG/nJ+\nJI7axu0AjM1tPjiiZfMLIo+9zdMnGIQrBkvFnLDRUehclbfLujAa5rHhyq4vYLEv\nIK+LWk+zJRjGz9ZB90VkoKVTB88hVm4e5sL0dnB9F9IU\n-----END ENCRYPTED PRIVATE KEY-----\n'
            c.Authenticator.rsa_private_key_password = 'mypassword'
            c.Authenticator.rsa_public_key_pem = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApbAH3Z397pRp/0peApCX\nPYvyMB1/F79z7BS89FZXiVBbIuw+TZJEfxFxuVfrg3jpWjDCPFnd/g3fG9Alr3JK\nMGOQ+f4r2UfMEZ/Glq52tLw6gsyfBEmn2haH0EQS6FPT6hdzZk3IjVwQ/iMm4+Tz\n3BD+NDXFURR4mopYtgpnbqV60Mbz29JC583w6kFyQHLx+5slBEvZgF5k5YWgmZ49\nCkQfc9zhPVDqzz2m7AuV2/lDrgTtkQmluW/o/XYryfriWc+D74a7/cyQuErEs9gh\nXIAZUPF82bE3VvPX2G1FP3OITO9uf9hqSuYAUfPwaxl1NMv11b/svYwvJPxawPz1\ngQIDAQAB\n-----END PUBLIC KEY-----\n'



To use the login from outside you may need to use one of the following JS scripts.


1. Code to log in into JupyterHub using plain text credentials::

    var myHeaders = new Headers();
    myHeaders.append("username", "userName");
    myHeaders.append("token", "userNameToken");
    var myInit = { method: 'GET',
                   headers: myHeaders,
                   mode: 'cors',
                   cache: 'default' };

    var myRequest = new Request('https://ibm-q-jupyter-hub.us-south.containers.appdomain.cloud/hub/login', myInit);
    fetch(myRequest).then(function(response) {
      return response.text();
    }).then(function(text) {
        document.write('<iframe src="https://ibm-q-jupyter-hub.us-south.containers.appdomain.cloud/user/userName/tree?" />')
    });


2. Code to log in into JupyterHub using encrypted credentials::

    var myHeaders = new Headers();
    myHeaders.append("username", "RSAEncryptedStringForTheUserName");
    myHeaders.append("token", "RSAEncryptedStringForTheToken");
    var myInit = { method: 'GET',
                   headers: myHeaders,
                   mode: 'cors',
                   cache: 'default' };
    var myRequest = new Request('https://ibm-q-jupyter-hub.us-south.containers.appdomain.cloud/hub/login', myInit);
    fetch(myRequest).then(function(response) {
      return response.text();
    }).then(function(text) {
        document.write('<iframe src="https://ibm-q-jupyter-hub.us-south.containers.appdomain.cloud/user/userName/tree?" />')
    });

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


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

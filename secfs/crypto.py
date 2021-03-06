# This file implements the crypto parts of SecFS

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from secfs.types import I, Principal, User, Group
import secfs.fs

keys = {}

def sign(obj, user):
    """
    Hashes an arbitrary object with and then signs with rsa
    """
    private_key = keys[user];
    signer = private_key.signer(
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    signer.update(obj)
    signature = signer.finalize()

    return signature

def verify(obj, signature, user):
    """
    Uses the built-in rsa signing verification
    If verification fails, raises cryptography.exceptions.InvalidSignature
    """
    if signature == {}:
        return False
    public_key = secfs.fs.usermap[user]
    verifier = public_key.verifier(
        signature,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    verifier.update(obj)
    verifier.verify()
    return True

def encrypt(user, data):
    # TODO: what about groups?
    public_key = secfs.fs.usermap[user]
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return ciphertext

def decrypt(user, ciphertext):
    private_key = keys[user]
    data = private_key.decrypt(
    ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return data

def register_keyfile(user, f):
    """
    Register the private key for the given user for use in signing/decrypting.
    """
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))

    with open(f, "rb") as key_file:
        k=key_file.read()
        keys[user] = serialization.load_pem_private_key(
            k,
            password=None,
            backend=default_backend()
        )

def decrypt_sym(key, data):
    """
    Decrypt the given data with the given key.
    """
    f = Fernet(key)
    return f.decrypt(data)

def encrypt_sym(key, data):
    """
    Encrypt the given data with the given key.
    """
    f = Fernet(key)
    return f.encrypt(data)

def generate_ephemeral_key():
    return Fernet.generate_key()

def generate_key(user):
    """
    Ensure that a private/public keypair exists in user-$uid-key.pem for the
    given user. If it does not, create one, and store the private key on disk.
    Finally, return the user's PEM-encoded public key.
    """
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    f = "user-{}-key.pem".format(user.id)

    import os.path
    if not os.path.isfile(f):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        pem = private_key.private_bytes(
           encoding=serialization.Encoding.PEM,
           format=serialization.PrivateFormat.TraditionalOpenSSL,
           encryption_algorithm=serialization.NoEncryption()
        )

        with open(f, "wb") as key_file:
            key_file.write(pem)

        public_key = private_key.public_key()
    else:
        with open(f, "rb") as key_file:
            public_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            ).public_key()

    return public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

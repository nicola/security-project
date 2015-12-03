# This file handles all interaction with the SecFS server's blob storage.

import hashlib
# a server connection handle is passed to us at mount time by secfs-fuse
server = None
def register(_server):
    global server
    server = _server

def store(blob):
    """
    Store the given blob at the server, and return the content's hash.
    """

    # We should protect against an adversarial server:
    # a server should never lie to us about the hash of our data
    chash = hashlib.sha224(blob).hexdigest()

    global server
    shash = server.store(blob)
    assert chash == shash, "UNTRUSTED SERVER: hash {} instead of {}".format(
        shash, chash)

    return chash

def load(chash):
    """
    Load the blob with the given content hash from the server.
    """
    global server
    blob = server.read(chash)

    # the RPC layer will base64 encode binary data
    if "data" in blob:
        import base64
        blob = base64.b64decode(blob["data"])

    return blob

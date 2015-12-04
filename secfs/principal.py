import json
import secfs.fs
import secfs.crypto
from secfs.types import User, Group
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

# Brought over from fs.py.

class UserMap:
    """
    Represents the contents of .users.
    """
    def __init__(self, initmap=None):
        self.keymap = initmap if initmap else {}
    def public_key(self, user):
        return self.keymap[user]
    def set_public_key(self, user, key):
        self.keymap[user] = key
    def from_blob(blob):
        plain_dict = json.loads(blob.decode('utf-8'))
        public_key = {}
        for u, pem in plain_dict.items():
            public_key[User(int(u))] = load_pem_public_key(
                pem.encode('utf-8'), backend=default_backend())
        return UserMap(public_key)
    def as_blob(self):
        plain_dict = {
            str(u.id): v.decode('utf-8') for u, v in self.keymap.items()
        }
        return json.dumps(plain_dict, indent=2).encode('utf-8')

# usermap contains a map from user ID to their public key according to /.users
usermap = UserMap()
# groupmap contains a map from group ID to the list of members according to /.groups
groupmap = {}


def is_member(user, group):
    if not group_exists(group):
        return False
    return user in groupmap[group]

def group_members(read_by, group):
    return groupmap[group]

def group_exists(group):
    return group in groupmap

def user_public_key(user):
    return usermap.public_key(user)

def set_root_public_key(user, public_key):
    """
    Used when bootstrapping a filesystem, before anything is loaded
    from the server.  We need a root identity who owns the root directory.
    """
    usermap.set_public_key(user, public_key)

def default_users_and_groups():
    """
    Used when creating a new filesystem.  Defines the users and groups
    objects that are later passed into init_files below.
    """
    users = {u: secfs.crypto.generate_key(u) for u in secfs.crypto.keys}
    groups = {Group(100): [u for u in secfs.crypto.keys if u.id != 666]}
    return (users, groups)

def init_files(users, groups):
    """
    Saves initial users and groups files.  TODO: Make a UserMap and
    GroupMap class, and serialize them here.
    """
    return {
        b".users": json.dumps(
                {str(u.id): v.decode('utf-8')
                    for u, v in users.items()},
                indent=2
            ).encode('utf-8'),
        b".groups": json.dumps(
                {str(g.id): [u.id for u in v]
                    for g, v in groups.items()},
                indent=2
            ).encode('utf-8')
    }

def reload():
    """
    Reloads users and groups files from the server.  TODO: Load into a
    UserMap and GroupMap class.
    """
    global usermap, groupmap
    def _read_file(fname):
        """
        Simple helper function for reading the pickled contents of a SecFS file
        located in the root of the file system.
        """
        return secfs.fs.get_inode(
                    # Ex3-note: root directory is unencrypted, read as none
                    secfs.store.tree.find_under(None, secfs.fs.root_i, fname)
                ).read(None)
                # Ex3-note: .users/.groups is not encrypted.

    # load group map
    # EC: just secfs.groups.clearknowledge()
    groupmap = {
        Group(int(g)): [User(u) for u in v]
        for g, v in json.loads(_read_file(b".groups").decode('utf-8')).items()}

    # load user public key map (and decode their PEM-encoded public keys)
    usermap = UserMap.from_blob(_read_file(b".users"))





# With anonymized groups, the metadata in the filesystem is now
# organized as follows:
# 
# .users is as-is, owned by root.
# .group-100 is a file, owned by group 100 and describing group 100.
# .group-111 is a file, owned by group 111 and describing group 111.
# 
# For now, the root user is in every group to facilitate setting up
# the fake groups.  Ultimately a utility could be created to update
# group membership and remove the root user from a group after it is
# created.
# 
# Even though .group-100 is world-readable, it contains contents that
# are meaningful only to members of group 100, and that enable those
# members to read non-world-readable files owned by group 100.  The
# system also knows how to read .groups/100 on behalf of any member
# of group 100.
# 
# The .group-100 file contains a special file format that can only be
# decrypted by members of group 100.
# 
# Here is the design of a .group-100 file.  It is a JSON blob:
# 
# { nonce: "f234123d",
#   keys: ["29135234", "123124242", ...],
#   payload: "4123r12312312312312"
# }
# 
# The nonce and the keys work together to hide a secret key visible
# only to group members.  The secret key encrypts the payload which is
# another JSON blob.  Decrypting the payload reveals:
# 
# {
#   secret: "12341234123132",  # group shared secret
#   members: [100,666,1000]    # user ids of group members
# }
# 
# Manipulation of this file is supported by a new class in groups.py
# like this:
#
#class GroupKnowledge:
#    def group_file(self, group):
#        if group not in self.files:
#            self.files[group] = load_file('.groups/{group}')
#            self.files[group] = None if no file
#        return self.files[group]
#    def group_membership(self, myself, group):
#        mkey = (myself, group)
#        if mkey not in self.knowledge:
#            file = self.group_file(group)
#            if not file:
#                membership = None
#            else:
#                membership = GroupMembership.from_anonymized_bytes(file)
#            self.knowledge[mkey] = membership
#        return self.knowledge[mkey]
#    def is_member(self, read_as, group):
#        membership = self.group_membership(self, read_as, group)
#        if membership is None:
#            return False
#        if read_as.id in membership.members:
#            return True
#        return False
#    def all_members(self, read_as, group):
#        membership = self.group_membership(self, read_as, group)
#        assert membership is not None
#        return membership.members
#    def group_secret(self, read_as, group):
#        membership = self.group_membership(self, read_as, group)
#        assert membership is not None
#        return membership.secret
#
#class GroupMembership:
#    def __init__(members=None, secret=None):
#        self.members = list(members) if members else []
#        self.secret = secret if secret else (newly generated secret)
#    def from_anonymized_bytes(read_as, bytes):
#        data = json.loads(bytes.decode('utf-8'))
#        nonce = data['nonce']
#        keys = data['keys']
#        payload = data['payload']
#        # 1. Hash read_as.id with the nonce to get a hash key
#        # 2. Try decrypting keys[h] keys[h+1], etc with my own private key
#        # 3. On failure, return None
#        # 4. On success, get the payload key and try using it to decrypt
#        #    the payload.
#        info = json.loads(cleartext_payload.decode('utf-8'))
#        return GroupMembership(info['members'], info['secret'])
#    def to_anonymized_bytes(self):
#        info = json.dumps({'secret': self.secret, 'members': self.members})
#        cleartext_payload = json.dumps(info)
#        payload_key = '' # TODO: make a random key
#        payload = cleartext_payload # TODO: encrypt with payload_key
#        keys = [] # TODO: make the actual keys
#        # 1. Pick 2^K > len(self.members)
#        # 2. Encrypt payload_key with each member's public key
#        # 3. Set up the hashtable and pad with encrypted garbage
#

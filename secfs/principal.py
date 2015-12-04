import json
import secfs.fs
import secfs.crypto
from secfs.types import User, Group
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

class GroupMap:
    """
    Represents the contents of .groups as an object that can answer
    questions about any group.  TODO: organize the .groups file
    in a different way.
    """
    def __init__(self, initmap=None):
        self.membermap = initmap if initmap else {}
        # EC: Change this to a map by users (maybe in addition
        # to a list of groups?)
    def is_member(self, user, group):
        # 1. Apply user's decryption key to check its group memberships
        if not self.exists(user, group):
            return False
        return user in self.membermap[group]
    def secret_key(self, read_as, group):
        # Returns the group secret key, if allowed to access it
        return b''
    def is_secret_group(self, read_as, group):
        # Returns true if the group is a secret group.
        # A secret group can own no world-readable files.
        return False
    def members(self, read_as, group):
        return self.membermap[group]
    def exists(self, read_as, group):
        # EC: see if the reader can tell that a given group exists.
        return group in self.membermap
    def from_blob(blob):
        plain_dict = json.loads(blob.decode('utf-8'))
        initmap = {}
        for g, lst in plain_dict.items():
            initmap[Group(int(g))] = [User(id) for id in lst]
        return GroupMap(initmap)
    def as_blob(self):
        plain_dict = {
            str(g.id): [u.id for u in lst]
                for g, lst in self.membermap.items()
        }
        return json.dumps(plain_dict, indent=2).encode('utf-8')

class UserMap:
    """
    Represents the contents of .users as an object that can
    retrieve public keys for users.
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
groupmap = GroupMap()

def is_member(user, group):
    return groupmap.is_member(user, group)

def group_members(read_as, group):
    return groupmap.members(read_as, group)

def group_exists(read_as, group):
    return groupmap.exists(read_as, group)

def is_secret_group(read_as, group):
    return groupmap.is_secret_group(read_as, group)

def group_secret_key(read_as, group):
    return groupmap.group_secret_key(read_as, group)

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
    return (UserMap(users), GroupMap(groups))

def init_files(initusers, initgroups):
    """
    Saves initial users and groups files.  TODO: Make a UserMap and
    GroupMap class, and serialize them here.
    """
    return {
        b".users": initusers.as_blob(),
        b".groups": initgroups.as_blob()
    }

def reload():
    """
    Reloads users and groups files from the server.  TODO: Load into a
    UserMap and GroupMap class.
    """
    global usermap, groupmap
    def _read_file(fname):
        """
        Simple helper function for reading the blob contents of a SecFS file
        located in the root of the file system.
        """
        return secfs.fs.get_inode(
                    # Ex3-note: root directory is unencrypted, read as none
                    secfs.store.tree.find_under(None, secfs.fs.root_i, fname)
                ).read(None) # Ex3-note: .users/.groups is not encrypted.

    # load group map
    groupmap = GroupMap.from_blob(_read_file(b".groups"))
    # load user public key map (and decode their PEM-encoded public keys)
    usermap = UserMap.from_blob(_read_file(b".users"))



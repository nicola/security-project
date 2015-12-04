import json
import secfs.fs
import secfs.crypto
import os.path
import pickle
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
    def __init__(self, initmap=None, peruserinit=None):
        self.membermap = initmap if initmap else {}
        self.perusermap = peruserinit if peruserinit else {}
        # EC: Change this to a map by users (maybe in addition
        # to a list of groups?)
    def is_member(self, user, group):
        # 1. Apply user's decryption key to check its group memberships
        if not self.exists(user, group):
            return False
        return user in self.membermap[group]['data']
    def secret_key(self, read_as, group):
        # Returns the group secret key, if allowed to access it.
        # read_as is the User asking the question.
        if self.is_secret_group(read_as, group):
            return b''
        else:
            if not self.is_member(read_as, group):
                raise PermissionError("User {} to read group secret key of group {} while not a member".format(read_as, group))
            enc_secret = self.perusermap[read_as][0][0]
            dec_secret = secfs.crypto.decrypt(read_as, enc_secret);
            return pickle.loads(dec_secret)
    def is_secret_group(self, read_as, group):
        # Returns true if the group is a secret group.
        # A secret group can own no world-readable files.
        # read_as is the User asking the question.
        
        # Check if group is encrypted or not
        return False
    def members(self, read_as, group):
        # Returns the members of the group, if allowed to see them.
        # read_as is the User asking the question.
        return self.membermap[group]['data']
    def exists(self, read_as, group):
        # EC: see if the reader can tell that a given group exists.
        # read_as is the User asking the question, and it is OK
        # for people not in a secret group to get "False".
        return group in self.membermap
    def from_blob(blob):
        # Load the GroupMap from a file.
        membermap, perusermap =  pickle.loads(blob)
        return GroupMap(membermap, perusermap)
    def as_blob(self):
        # Save the GroupMap to a file.
        return pickle.dumps((self.membermap, self.perusermap))

class UserMap:
    """
    Represents the contents of .users as an object that can
    retrieve public keys for users.
    """
    def __init__(self, initmap=None):
        self.keymap = initmap if initmap else {}
    def public_key(self, user):
        print ("getting user public key from map:", self.keymap)
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
    return groupmap.secret_key(read_as, group)

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
    uset = set(
            list(secfs.crypto.keys.keys()) +
            [User(uid) for uid in range(1001, 1006)])
    users = {u: secfs.crypto.generate_key(u) for u in uset}

    secret = secfs.crypto.generate_sym_key()
    print ("FIRST GROUP SECRET:", secret)
    isSecret = False
    groups = {
        Group(100): {'data':[u for u in secfs.crypto.keys if u.id != 666], 
                     'secret': secret,
                     'isSecret':isSecret}
    }

    # Create per-user group list
    per_user = {}
    for g, lst in groups.items():
        userlist = lst['data']
        for u in userlist:
            if u in per_user:
                per_user[u].append[(g, lst['isSecret'])]
            else:
                per_user[u] = [(g, lst['isSecret'])]
            user_pk = load_pem_public_key(users[u], backend=default_backend())
            if lst['isSecret']:
                gp_info = pickle.dumps((per_user[u][-1][0], lst['secret']))
                per_user[u][-1] = (secfs.crypto.encrypt_asym(user_pk, gp_info), lst['isSecret'])
            else:
                secret_info = pickle.dumps(lst['secret'])
                per_user[u][-1] = (secfs.crypto.encrypt_asym(user_pk, secret_info), lst['isSecret'], g)
    print("PER USER:", per_user)

    # Encrypt the secret groups
    for g, lst in groups.items():
        if lst['isSecret']:
            lst['data'] = secfs.crypto.encrypt_sym(secret, pickle.dumps(lst['data']))

    return (UserMap(users), GroupMap(groups, per_user))

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



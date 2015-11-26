# This file contains all code handling the resolution and modification of i
# mappings. This includes group handle indirection and VSL validation, so the
# file is somewhat hairy.
# NOTE: an ihandle is the hash of a principal's itable, which holds that
# principal's mapping from inumbers (the second part of an i) to inode hashes.

import pickle
import secfs.store
import secfs.fs
from secfs.types import I, Principal, User, Group
import secfs.crypto as crypto

# vsl represents the current view of the file system's VSL

# Ex1: this is new.
class VersionStructureList:
    def __init__(self):
        # Ex1: The latest seen server version vector
        self.current_versions = {}  # map Principal -> version integer
        # Ex1: Any recent local changes are accumulated
        self.version_delta = set()  # set of Principals
        # Ex1: All the VS's one for each users, in a map user -> VS.
        self.version_structures = {}  # map Principal -> VersionStructure
        # Ex1: table of all the latest itable hashes, in a map
        self.current_ihandles = {}  # map Principal -> hash
        # Ex1: finally include the current_itables cache
        # current_itables represents the current view of the itables
        self.current_itables = {}  # principal -> itable.

    def lookup_itable(self, principal):
        # Ex1: will get an itable, including downloading a missing itable
        # 1. First it will check if current_itables has it already - quick.
        if principal in self.current_itables:
            return self.current_itables[principal]
        # 2. Then it will check current_ihandles
        #    if it has it, it will download it and update current_itables.
        if principal in self.current_ihandles:
            loaded_table = Itable.load(self.current_ihandles[principal])
            self.current_itables[principal] = loaded_table
            return loaded_table
        # 3. Not there either? Return None.
        return None

    def set_itable(self, update_as, update_for, itable):
        # Ex1: will also update "as" VS with a new itable.
        # 1. check "for" could be a group or, if it is a user, same as "as"
        if update_as.is_user() and update_as != update_for:
            raise TypeError("user itable can only be updated by the same user.")

        # 2. the itable gets saved to the server and hashed.
        new_hash = secfs.store.block.store(itable.bytes())
        # TODO: do we really want to trust the server hash?
        # BUG: If the server is adversarial, we should only trust our own hash.

        # 3. current_versions get increments for update_as and update_for
        # and version_delta is update to note changes
        increment_version(self.current_versions, update_as)
        self.version_delta.add(update_as)
        print("{} updating itable for {}, now version {}".format(update_as, update_for, self.current_versions[update_as]))
        if update_for != update_as:
            increment_version(self.current_versions, update_for)
            self.version_delta.add(update_for)

        # 3.5. Update current_itables
        self.current_itables[update_for] = itable

        # 4. the VS is updated with the new itable hash.
        vs = self.version_structures.get(update_as, None)
        if vs is None:
            vs = VersionStructure()
            self.version_structures[update_as] = vs
        vs.ihandles[update_for] = new_hash

        # 5. the VS is updated with the current current_versions
        # TODO: security check needed here.
        # we should have a secureUpdate function
        vs.version_vector.update(self.current_versions)

        # 6. signing is done here.
        vs.sign(update_as)

        # 7. TODO: consider performance
        # can any of the above work be delayed until upload?


    def upload(self):
        # Ex1: will push a new VSL up to the server.
        # 1. Call the new server RPC "uploadVSL".
        # Could upload diffs based on version_delta.
        changed_vsl = {}
        for user in self.version_delta:
            if user.is_user():
                vs = self.version_structures[user]
                ver = self.current_versions[user]
                changed_vsl[user.id] = (ver, vs.bytes())
        server.uploadVSL(changed_vsl)

        # 2. After upload version_delta is emptied.
        self.version_delta.clear()

    def download(self):
        # Ex1: refresh the VSL based on the latest from the server.
        # 1. Call the new server RPC "downloadVSL".
        user_versions = {
           user.id: self.current_versions[user]
           for user in self.current_versions.keys() if user.is_user()
        }
        changed_vsl = server.downloadVSL({}) # user_versions)

        # 2. TODO: verify security properties of the downloaded VSL.
        # No going back in time.

        # Verifying all of the vs's
        # loop through all vs's and call verify throw if bad
        # crypto library throws InvalidSignature exception if verification fails
        for uid, vsbytes in changed_vsl.items():
            vs = VersionStructure.from_bytes(vsbytes)
            user = {}
            for u in self.current_versions.keys():
                 if (u.id == uid):
                     user = u
            vs.verify(user)

        # 3. After download, set current_versions to the latest
        # version numbers in each VSL.
        new_versions = {}
        for uid, vsbytes in changed_vsl.items():
            # TODO: verify that the version is actually newer.
            vs = VersionStructure.from_bytes(vsbytes)
            self.version_structures[User(uid)] = vs
            for principal, version in vs.version_vector.items():
                if self.current_versions.get(principal, -1) <= version:
                    # 4. Latest itable hashes (current_ihandles) are updated.
                    if principal in vs.ihandles and (vs.ihandles[principal] !=
                            self.current_ihandles.get(principal, None)):
                        self.current_ihandles[principal] = \
                                vs.ihandles[principal]
                        # 5. If an itable hash is changed
                        # deleted the old itable from current_itables.
                        if principal in self.current_itables:
                            del self.current_itables[principal]

# Ex1: this is the singleton client cache
vsl = VersionStructureList()

# a server connection handle is passed to us at mount time by secfs-fuse
server = None
def register(_server):
    global server
    server = _server

def pre(refresh, user):
    """
    Called before all user file system operations, right after we have obtained
    an exclusive server lock.
    """
    # Ex1: download updates to the VSL before doing operations
    vsl.download()
    if refresh != None:
        # refresh usermap and groupmap
        refresh()

def post(push_vs):
    if not push_vs:
        # when creating a root, we should not push a VS (yet)
        # you will probably want to leave this here and
        # put your post() code instead of "pass" below.
        return
    # Ex1: upload updates to the VSL before doing operations
    vsl.upload()

# Ex1: review.  This is an easy-to-pickle type that just has two maps.
class VersionStructure:
    def __init__(self):
        self.ihandles = {
                # map Principal -> itable hashes
        }
        self.version_vector = {
                # map Principal -> integer versions
        }
        # TODO: owner user?  signature?
        self.signature = {
               # signature
        }

    def from_bytes(b):
        # the RPC layer will base64 encode binary data
        if "data" in b:
            import base64
            b = base64.b64decode(b["data"])
        t = VersionStructure()
        t.ihandles, t.version_vector, t.signature = pickle.loads(b)
        return t

    def bytes(self):
        return pickle.dumps((self.ihandles, self.version_vector, self.signature))

    def sign(self, user):
        # updates the signature part of the vs
        self.signature = crypto.sign(self.bytes(), user)

    def verify(self, user):
        # verifies a signature
        return crypto.verify(self.bytes(), self.signature, user)

class Itable:
    """
    An itable holds a particular principal's mappings from inumber (the second
    element in an i tuple) to an inode hash for users, and to a user's i for
    groups.
    """
    def __init__(self):
        self.mapping = {}

    def load(ihandle):
        b = secfs.store.block.load(ihandle)
        if b == None:
            return None

        t = Itable()
        t.mapping = pickle.loads(b)
        return t

    def bytes(self):
        return pickle.dumps(self.mapping)

def resolve(i, resolve_groups = True):
    """
    Resolve the given i into an inode hash. If resolve_groups is not set, group
    is will only be resolved to their user i, but not further.

    In particular, for some i = (principal, inumber), we first find the itable
    for the principal, and then find the inumber-th element of that table. If
    the principal was a user, we return the value of that element. If not, we
    have a group i, which we resolve again to get the ihash set by the last
    user to write the group i.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    principal = i.p

    if not isinstance(principal, Principal):
        raise TypeError("{} is not a Principal, is a {}".format(principal, type(principal)))

    if not i.allocated():
        # someone is trying to look up an i that has not yet been allocated
        return None

    # Ex1: now using vsl.lookup_itable instead of current_itables
    t = vsl.lookup_itable(principal)
    if t is None:
        # User does not yet have an itable
        print("resolving {} could not find itable for {}".format(i, principal))
        return None 

    if i.n not in t.mapping:
        raise LookupError("principal {} does not have i {}".format(principal, i))

    # santity checks
    if principal.is_group() and not isinstance(t.mapping[i.n], I):
        raise TypeError("looking up group i, but did not get indirection ihash")
    if principal.is_user() and isinstance(t.mapping[i.n], I):
        raise TypeError("looking up user i, but got indirection ihash")

    if isinstance(t.mapping[i.n], I) and resolve_groups:
        # we're looking up a group i
        # follow the indirection
        return resolve(t.mapping[i.n])

    return t.mapping[i.n]

def modmap(mod_as, i, ihash):
    """
    Changes or allocates i so it points to ihash.

    If i.allocated() is false (i.e. the I was created without an i-number), a
    new i-number will be allocated for the principal i.p. This function is
    complicated by the fact that i might be a group i, in which case we need
    to:

      1. Allocate an i as mod_as
      2. Allocate/change the group i to point to the new i above

    modmap returns the mapped i, with i.n filled in if the passed i was no
    allocated.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(mod_as, User):
        raise TypeError("{} is not a User, is a {}".format(mod_as, type(mod_as)))

    assert mod_as.is_user() # only real users can mod

    if mod_as != i.p:
        print("trying to mod object for {} through {}".format(i.p, mod_as))
        assert i.p.is_group() # if not for self, then must be for group

        real_i = resolve(i, False)
        if isinstance(real_i, I) and real_i.p == mod_as:
            # We updated the file most recently, so we can just update our i.
            # No need to change the group i at all.
            # This is an optimization.
            i = real_i
        elif isinstance(real_i, I) or real_i == None:
            if isinstance(ihash, I):
                # Caller has done the work for us, so we just need to link up
                # the group entry.
                print("mapping", i, "to", ihash, "which again points to", resolve(ihash))
            else:
                # Allocate a new entry for mod_as, and continue as though ihash
                # was that new i.
                # XXX: kind of unnecessary to send two VS for this
                _ihash = ihash
                ihash = modmap(mod_as, I(mod_as), ihash)
                print("mapping", i, "to", ihash, "which again points to", _ihash)
        else:
            # This is not a group i!
            # User is trying to overwrite something they don't own!
            raise PermissionError("illegal modmap; tried to mod i {0} as {1}".format(i, mod_as))

    # find (or create) the principal's itable
    # Ex1: useing vsl.lookup_itable
    t = vsl.lookup_itable(i.p)
    if t is None:
        if i.allocated():
            # this was unexpected;
            # user did not have an itable, but an inumber was given
            raise ReferenceError("itable not available")
        t = Itable()
        print("no current list for principal", i.p, "; creating empty table", t.mapping)

    # look up (or allocate) the inumber for the i we want to modify
    if not i.allocated():
        inumber = 0
        while inumber in t.mapping:
            inumber += 1
        i.allocate(inumber)
        print("allocated {}".format(i))
    else:
        if i.n not in t.mapping:
            raise IndexError("invalid inumber")

    # modify the entry, and store back the updated itable
    if i.p.is_group():
        print("mapping", i.n, "for group", i.p, "into", t.mapping)
    t.mapping[i.n] = ihash # for groups, ihash is an i
    # Ex1: use vs.set_itable instead of directly changing current_itables
    vsl.set_itable(mod_as, i.p, t)
    return i

def increment_version(vv, key):
    vv[key] = vv.get(key, 0) + 1

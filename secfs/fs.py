# This file implements file system operations at the level of inodes.

import time
import secfs.crypto
import secfs.tables
import secfs.access
import secfs.store.tree
import secfs.store.block
from secfs.store.inode import Inode
from secfs.store.tree import Directory
from cryptography.fernet import Fernet
from secfs.types import I, Principal, User, Group

# usermap contains a map from user ID to their public key according to /.users
usermap = {}
# groupmap contains a map from group ID to the list of members according to /.groups
groupmap = {}
# owner is the user principal that owns the current share
owner = None
# root_i is the i of the root of the current share
root_i = None

def get_inode(i):
    """
    Shortcut for retrieving an inode given its i.
    """
    ihash = secfs.tables.resolve(i)
    if ihash == None:
        raise LookupError("asked to resolve i {}, but i does not exist".format(i))

    return Inode.load(ihash)

def init(owner, users, groups):
    """
    init will initialize a new share root as the given user principal. This
    includes setting up . and .. in the root directory, as well as adding the
    .users and .groups files that list trusted user public keys and group
    memberships respectively. This function will only allocate the share's
    root, but not map it to any particular share at the server. The new root's
    i is returned so that this can be done by the caller.
    """
    if not isinstance(owner, User):
        raise TypeError("{} is not a User, is a {}".format(owner, type(owner)))

    node = Inode()
    node.kind = 0
    node.ex = True
    node.owner = owner
    node.ctime = time.time()
    node.mtime = node.ctime

    ihash = secfs.store.block.store(node.bytes())
    root_i = secfs.tables.modmap(owner, I(owner), ihash)
    if root_i == None:
        raise RuntimeError

    # Ex3-note: tree.add uses owner for any encryption needed (not needed)
    new_ihash = secfs.store.tree.add(owner, root_i, b'.', root_i)
    secfs.tables.modmap(owner, root_i, new_ihash)
    new_ihash = secfs.store.tree.add(owner, root_i, b'..', root_i)
    secfs.tables.modmap(owner, root_i, new_ihash)
    print("CREATED ROOT AT", new_ihash)

    init = {
        b".users": users,
        b".groups": groups,
    }

    import pickle
    for fn, c in init.items():
        bts = pickle.dumps(c)

        node = Inode()
        node.kind = 1
        node.size = len(bts)
        node.mtime = node.ctime
        node.ctime = time.time()
        # Ex3-note: write(owner) encrypts if if needed (not needed).
        node.write(owner, bts)

        ihash = secfs.store.block.store(node.bytes())
        i = secfs.tables.modmap(owner, I(owner), ihash)
        link(owner, i, root_i, fn)

    return root_i

def _create(parent_i, name, create_as, create_for, isdir, encrypt):
    """
    _create allocates a new file, and links it into the directory at parent_i
    with the given name. The new file is owned by create_for, but is created
    using the credentials of create_as. This distinction is necessary as a user
    principal is needed for the final i when creating a file as a group.
    """
    # TODO: when encrypted, figure out what to do with keys and encryption.
    if not isinstance(parent_i, I):
        raise TypeError("{} is not an I, is a {}".format(parent_i, type(parent_i)))
    if not isinstance(create_as, User):
        raise TypeError("{} is not a User, is a {}".format(create_as, type(create_as)))
    if not isinstance(create_for, Principal):
        raise TypeError("{} is not a Principal, is a {}".format(create_for, type(create_for)))

    assert create_as.is_user() # only users can create
    assert create_as == create_for or create_for.is_group() # create for yourself or for a group
    if create_for.is_group() and create_for not in groupmap:
        raise PermissionError("cannot create for unknown group {}".format(create_for))

    # This check is performed by link() below, but better to fail fast
    if not secfs.access.can_write(create_as, parent_i):
        if parent_i.p.is_group():
            raise PermissionError("cannot create in group-writeable directory {0} as {1}; user is not in group".format(parent_i, create_as))
        else:
            raise PermissionError("cannot create in user-writeable directory {0} as {1}".format(parent_i, create_as))

    node = Inode()
    node.ctime = time.time()
    node.mtime = node.ctime
    node.kind = 0 if isdir else 1
    node.ex = isdir
    # Ex3-note: set node.encryptfor = create_for instead
    if encrypt:
        node.encryptfor = create_for
    else:
        node.encryptfor = None

    # Here, we followed the recommendations.  We did the following:
    #
    #  - store the newly created inode (node.bytes()) on the server
    ihash = secfs.store.block.store(node.bytes())

    #  - map that block to an i owned by the user
    i = secfs.tables.modmap(create_as, I(create_as), ihash)

    #  - if a directory is being created, create entries for . and ..
    if isdir:
        # Ex3-note: Send create_as to do encryption for dir.
        new_ihash = secfs.store.tree.add(create_as, i, b'.', i)
        secfs.tables.modmap(create_as, i, new_ihash)
        new_ihash = secfs.store.tree.add(create_as, i, b'..', parent_i)
        secfs.tables.modmap(create_as, i, new_ihash)

    #  - if create_for is a group, you will also have to create a group i for
    #    that group, and point it to the user's i
    if create_for.is_group():
        i = secfs.tables.modmap(create_as, I(create_for), i)

    #  - call link() to link the new i into the directory at parent_i with the
    #    given name
    link(create_as, i, parent_i, name)
    #
    # Also make sure that you *return the final i* for the new inode!
    return i

def create(parent_i, name, create_as, create_for, encrypt):
    """
    Create a new file.
    See secfs.fs._create
    """
    return _create(parent_i, name, create_as, create_for, False, encrypt)

def mkdir(parent_i, name, create_as, create_for, encrypt):
    """
    Create a new directory.
    See secfs.fs._create
    """
    return _create(parent_i, name, create_as, create_for, True, encrypt)

def read(read_as, i, off, size):
    """
    Read reads [off:off+size] bytes from the file at i.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(read_as, User):
        raise TypeError("{} is not a User, is a {}".format(read_as, type(read_as)))
    print("fs is calling can_read({}, {})".format(read_as, i))
    if not secfs.access.can_read(read_as, i):
        if i.p.is_group():
            raise PermissionError("cannot read from group-readable file {0} as {1}; user is not in group".format(i, read_as))
        else:
            raise PermissionError("cannot read from user-readable file {0} as {1}".format(i, read_as))

    # Ex3-note: add read_as to read
    return get_inode(i).read(read_as)[off:off+size]

def write(write_as, i, off, buf):
    """
    Write writes the given bytes into the file at i at the given offset.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(write_as, User):
        raise TypeError("{} is not a User, is a {}".format(write_as, type(write_as)))

    if not secfs.access.can_write(write_as, i):
        if i.p.is_group():
            raise PermissionError("cannot write to group-owned file {0} as {1}; user is not in group".format(i, write_as))
        else:
            raise PermissionError("cannot write to user-owned file {0} as {1}".format(i, write_as))

    node = get_inode(i)

    # TODO: this is obviously stupid -- should not get rid of blocks that haven't changed
    # Ex3-note: pass write_as for read_as
    bts = node.read(write_as)

    # write also allows us to extend a file
    if off + len(buf) > len(bts):
        bts = bts[:off] + buf
    else:
        bts = bts[:off] + buf + bts[off+len(buf):]

    # update the inode
    # Ex3-notes: use "write" to encrypt bytes if needed.
    node.write(write_as, bts)
    node.mtime = time.time()
    node.size = len(bts)

    # put new hash in tree
    new_hash = secfs.store.block.store(node.bytes())
    secfs.tables.modmap(write_as, i, new_hash)

    return len(buf)

def readdir(read_as, i, off):
    """
    Return a list of is in the directory at i.
    The directory is decrypted (if needed) using the user read_as.
    Each returned list item is a tuple of an i and an index. The index can be
    used to request a suffix of the list at a later time.
    """
    # Ex3-note: pass read_as for decrypting directory
    dr = Directory(i, read_as)
    if dr == None:
        return None

    return [(i, index+1) for index, i in enumerate(dr.children) if index >= off]

def link(link_as, i, parent_i, name):
    """
    Adds the given i into the given parent directory under the given name.
    """
    if not isinstance(parent_i, I):
        raise TypeError("{} is not an I, is a {}".format(parent_i, type(parent_i)))
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(link_as, User):
        raise TypeError("{} is not a User, is a {}".format(link_as, type(link_as)))
    if not secfs.access.can_write(link_as, parent_i):
        if parent_i.p.is_group():
            raise PermissionError("cannot create in group-writeable directory {0} as {1}; user is not in group".format(parent_i, link_as))
        else:
            raise PermissionError("cannot create in user-writeable directory {0} as {1}".format(parent_i, link_as))

    # Ex3-note: Send link_as to tree.add for decryption
    parent_ihash = secfs.store.tree.add(link_as, parent_i, name, i)
    secfs.tables.modmap(link_as, parent_i, parent_ihash)

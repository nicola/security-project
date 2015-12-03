import secfs.fs
from secfs.types import I, Principal, User, Group

def can_read(user, i):
    """
    Returns True if the given user can read the given i.
    """
    print("In can_read checking {} vs {}".format(user, i))
    # Under our rules, any user who can write a file can also read it;
    # this check is done first because it doesn't need to hit the network.
    if can_write(user, i):
        return True

    # Some files are world-readable.  We need the inode to know that.
    n = secfs.fs.get_inode(i)
    # Ex3-note: encryptfor is None if the file is world-readble.
    if not n.encryptfor:
        return True
    # Ex3-note: return false if our user is not listed in the readkey.
    # TODO: consider whether we really want to do this.
    if n.readkey and user in n.readkey:
        return True
    return False

def can_write(user, i):
    """
    Returns True if the given user can modify the given i.
    """
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))

    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    # If i is owned by a user, and that user isn't you, you can't write
    if i.p.is_user() and i.p != user:
        return False

    # if i.p.is_group, check secfs.groups.is_member(user, i.p)
    # If a group owns i, and you aren't in the group, you can't write
    if i.p.is_group() and (i.p not in secfs.fs.groupmap or user not in secfs.fs.groupmap[i.p]):
        return False

    return True

def can_execute(user, i):
    """
    Returns True if the given user can execute the given i.
    """
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))

    if not secfs.access.can_read(user, i):
        return False

    # check x bits
    node = secfs.fs.get_inode(i)
    return node.ex

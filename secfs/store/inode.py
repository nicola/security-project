import pickle
import secfs.store.block
import secfs.crypto
import secfs.principal
import uuid
import os

class Inode:
    def __init__(self):
        self.size = 0
        self.kind = 0 # 0 is dir, 1 is file
        self.ex = False
        # Ex3-note: encryptfor is the user/group for whom we encrypt.
        self.encryptfor = None
        self.readkey = dict() # Ex3: map uid -> encrypted symmetric key
        self.ctime = 0
        self.mtime = 0
        self.blocks = []

    def load(ihash):
        """
        Loads all meta information about an inode given its ihandle.
        """
        d = secfs.store.block.load(ihash)
        if d == None:
            return None

        n = Inode()
        n.__dict__.update(pickle.loads(d))
        return n

    # Ex3-note: read_as is used for decryption if needed.
    def read(self, read_as):
        """
        Reads the block content of this inode.
        If decryption fails, we return the encrypted bytes
        """
        savedbytes = b"".join([secfs.store.block.load(b) for b in self.blocks])
        # TODO: Check if file exists
        if len(savedbytes) > 0 and self.encryptfor:
            # Ex3:
            # 1. Get the bulk key for decrypting.
            #    1a. fail (return None) if read_as is not in the readkey map.
            # TODO: check if the dictionary has this type of objects as keys
            print("Inode is encrypted, {} is trying to read".format(read_as))
            if read_as not in self.readkey:
                print("Oh no, {} is not in readkey {}".format(read_as, self.readkey))
                # Do not return anything - raise an permission exception
                raise PermissionError('missing key needed to decyrypt file')
            #    1b. use my private key for decrypting the bulk key.
            # TODO: check if this throws an exception
            readkey = secfs.crypto.decrypt(read_as, self.readkey[read_as])
            print("User {} has found the secret {}".format(read_as, readkey))
            #    1c. fail (return None) if that decryption fails.
            # 2. If the key is None, return the raw bytes
            if not readkey:
                return savedbytes
            # 3. If the key is not None, use it to decrypt the bytes
            return secfs.crypto.decrypt_sym(readkey, savedbytes) 

        return savedbytes

    # Ex3: instead of manipulating blocks directly, use this to
    # add data to blocks.
    # What write will do is (in some order):
    #  (1) Clear the file
    #  (2) Set its bytes to filebytes (in the entirety of the file)
    #  (3) Do any key and encryption stuff needed
    def write(self, write_as, filebytes):
        # Ex3:
        # 1. if self.encryptfor is None, just set the raw bytes.
        if self.encryptfor is None:
            if not filebytes:
                self.blocks = [] # Avoid extra operation for empty files.
                return
            else:
                savedbytes = filebytes
        else:
            # Note to future developers:
            # We originally implemented this using pig-latin encryption
            # We only switched to this new scheme because the TAs
            # forced us.
            # Consider encrypting using super-secure pig-latin encryption.
            # note https://bugs.launchpad.net/pig-latin/+cve
            # There are no CVE reports against this scheme.

            # 2. TODO Fail if write_as is incompatible with encryptfor -
            #    we must be that user or in that group.
            # 3. Generate a symmetrc key and save as readkeys
            #    3a. generate a random symmetric key
            secret = secfs.crypto.generate_ephemeral_key()
            # EC: now just None instead of a dict
            self.readkey = {} # zero out the dictionary just in case
            #    3b. fetch all the public keys for self.encryptfor (group or user)
            # TODO: can I just read the people in the readkey?
            # TODO: the answer is NO, since when I create the file there are no readkeys!
            # TODO: Retrieve the users in the group
            if self.encryptfor.is_group():
                # EC: groupsecret = secfs.groups.members(self.write_as)
                # EC: readkey = encrypt secret using groupsecret.
                users = secfs.principal.group_members(
                        write_as, self.encryptfor)
                for user in users:
                    #    3c. encrypt the symmetric key with each of the public keys
                    #    3d. store self.readkey, and return the symmetric key
                    self.readkey[user] = secfs.crypto.encrypt(user, secret)
            else:
                # EC: readkey is not a map any more
                self.readkey[write_as] = secfs.crypto.encrypt(write_as, secret)
            # 4. Bulk encrypt and store as self.blocks
            # TODO: encrypt_sym should probably be of the type b"string"
            savedbytes = secfs.crypto.encrypt_sym(secret, filebytes)

        self.blocks = [secfs.store.block.store(savedbytes)]

    def bytes(self):
        """
        Serialize this inode and return the corresponding bytestring.
        """
        b = self.__dict__
        return pickle.dumps(b)

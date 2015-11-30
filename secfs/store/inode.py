import pickle
import secfs.store.block
import secfs.crypto
import uuid

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
        """

       savedbytes = b"".join([secfs.store.block.load(b) for b in self.blocks])
        if self.encryptfor:
            # Ex3:
            # 1. Get the bulk key for decrypting.
            #    1a. fail (return None) if read_as is not in the readkey map.
            # TODO: check if the dictionary has this type of objects as keys
            if read_as not in self.readkey:
                return None
            #    1b. use my private key for decrypting the bulk key.
            # TODO: check if this throws an exception
            readkey = secfs.crypto.decrypt(read_as, self.readkey[read_as])
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

            # 2. Fail if write_as is incompatible with encryptfor -
            #    we must be that user or in that group.
            # 3. Generate a symmetrc key and save as readkeys
            #    3a. generate a random symmetric key
            secret = uuid.uuid4() 
            #    3b. fetch all the public keys for self.encryptfor (group or user)
            # TODO: can I just read the people in the readkey?
            users = self.readkey.keys() 
            for user in users:
                #    3c. encrypt the symmetric key with each of the public keys
                #    3d. store self.readkey, and return the symmetric key
                self.readkey[user] = secfs.crypto.encrypt(user, secret)
            # 4. Bulk encrypt and store as self.blocks
            savedbytes = secfs.crypto.encrypt_sym(readkey, filebytes)

        self.blocks = [secfs.store.block.store(savedbytes)]

    def bytes(self):
        """
        Serialize this inode and return the corresponding bytestring.
        """
        b = self.__dict__
        return pickle.dumps(b)

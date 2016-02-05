from __future__ import absolute_import, print_function
# This is a skeleton created by zproject.  You can enhance the methods
# of these classes.
from . import plain


class CZMQError(Exception):
    pass


class Zactor(plain.Zactor):
    def __init__(self, *args, **kw):
        """
        Create a new actor passing arbitrary arguments reference.
        """
        plain.Zactor.__init__(*args, **kw)

    def send(self, msg_p):
        """
        Send a zmsg message to the actor, take ownership of the message
and destroy when it has been sent.
        """
        return plain.Zactor.send(self, msg_p)

    def recv(self):
        """
        Receive a zmsg message from the actor. Returns NULL if the actor
was interrupted before the message could be received, or if there
was a timeout on the actor.
        """
        return plain.Zactor.recv(self)

    @staticmethod
    def is_(self):
        """
        Probe the supplied object, and report if it looks like a zactor_t.
        """
        return plain.Zactor.is_(self)

    @staticmethod
    def resolve(self):
        """
        Probe the supplied reference. If it looks like a zactor_t instance,
return the underlying libzmq actor handle; else if it looks like
a libzmq actor handle, return the supplied value.
        """
        return plain.Zactor.resolve(self)

    def sock(self):
        """
        Return the actor's zsock handle. Use this when you absolutely need
to work with the zsock instance rather than the actor.
        """
        return plain.Zactor.sock(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zactor.test(verbose)



class Zarmour(plain.Zarmour):
    def __init__(self, *args, **kw):
        """
        Create a new zarmour.
        """
        plain.Zarmour.__init__(*args, **kw)

    def encode(self, data, size):
        """
        Encode a stream of bytes into an armoured string. Returns the armoured
string, or NULL if there was insufficient memory available to allocate
a new string.
        """
        return plain.Zarmour.encode(self, data, size)

    def decode(self, data, decode_size):
        """
        Decode an armoured string into a string of bytes.
The decoded output is null-terminated, so it may be treated
as a string, if that's what it was prior to encoding.
        """
        return plain.Zarmour.decode(self, data, decode_size)

    def mode(self):
        """
        Get the mode property.
        """
        return plain.Zarmour.mode(self)

    def mode_str(self):
        """
        Get printable string for mode.
        """
        return plain.Zarmour.mode_str(self)

    def set_mode(self, mode):
        """
        Set the mode property.
        """
        return plain.Zarmour.set_mode(self, mode)

    def pad(self):
        """
        Return true if padding is turned on.
        """
        return plain.Zarmour.pad(self)

    def set_pad(self, pad):
        """
        Turn padding on or off. Default is on.
        """
        return plain.Zarmour.set_pad(self, pad)

    def pad_char(self):
        """
        Get the padding character.
        """
        return plain.Zarmour.pad_char(self)

    def set_pad_char(self, pad_char):
        """
        Set the padding character.
        """
        return plain.Zarmour.set_pad_char(self, pad_char)

    def line_breaks(self):
        """
        Return if splitting output into lines is turned on. Default is off.
        """
        return plain.Zarmour.line_breaks(self)

    def set_line_breaks(self, line_breaks):
        """
        Turn splitting output into lines on or off.
        """
        return plain.Zarmour.set_line_breaks(self, line_breaks)

    def line_length(self):
        """
        Get the line length used for splitting lines.
        """
        return plain.Zarmour.line_length(self)

    def set_line_length(self, line_length):
        """
        Set the line length used for splitting lines.
        """
        return plain.Zarmour.set_line_length(self, line_length)

    def print_(self):
        """
        Print properties of object
        """
        return plain.Zarmour.print_(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zarmour.test(verbose)



class Zcert(plain.Zcert):
    def __init__(self, *args, **kw):
        """
        Create and initialize a new certificate in memory
        """
        plain.Zcert.__init__(*args, **kw)

    @staticmethod
    def new_from(public_key, secret_key):
        """
        Accepts public/secret key pair from caller
        """
        return plain.Zcert.new_from(public_key, secret_key)

    @staticmethod
    def load(filename):
        """
        Load certificate from file
        """
        return plain.Zcert.load(filename)

    def public_key(self):
        """
        Return public part of key pair as 32-byte binary string
        """
        return plain.Zcert.public_key(self)

    def secret_key(self):
        """
        Return secret part of key pair as 32-byte binary string
        """
        return plain.Zcert.secret_key(self)

    def public_txt(self):
        """
        Return public part of key pair as Z85 armored string
        """
        return plain.Zcert.public_txt(self)

    def secret_txt(self):
        """
        Return secret part of key pair as Z85 armored string
        """
        return plain.Zcert.secret_txt(self)

    def set_meta(self, name, format, *args):
        """
        Set certificate metadata from formatted string.
        """
        return plain.Zcert.set_meta(self, name, format, *args)

    def unset_meta(self, name):
        """
        Unset certificate metadata.
        """
        return plain.Zcert.unset_meta(self, name)

    def meta(self, name):
        """
        Get metadata value from certificate; if the metadata value doesn't
exist, returns NULL.
        """
        return plain.Zcert.meta(self, name)

    def meta_keys(self):
        """
        Get list of metadata fields from certificate. Caller is responsible for
destroying list. Caller should not modify the values of list items.
        """
        return plain.Zcert.meta_keys(self)

    def save(self, filename):
        """
        Save full certificate (public + secret) to file for persistent storage
This creates one public file and one secret file (filename + "_secret").
        """
        return plain.Zcert.save(self, filename)

    def save_public(self, filename):
        """
        Save public certificate only to file for persistent storage
        """
        return plain.Zcert.save_public(self, filename)

    def save_secret(self, filename):
        """
        Save secret certificate only to file for persistent storage
        """
        return plain.Zcert.save_secret(self, filename)

    def apply(self, zocket):
        """
        Apply certificate to socket, i.e. use for CURVE security on socket.
If certificate was loaded from public file, the secret key will be
undefined, and this certificate will not work successfully.
        """
        return plain.Zcert.apply(self, zocket)

    def dup(self):
        """
        Return copy of certificate; if certificate is NULL or we exhausted
heap memory, returns NULL.
        """
        return plain.Zcert.dup(self)

    def eq(self, compare):
        """
        Return true if two certificates have the same keys
        """
        return plain.Zcert.eq(self, compare)

    def print_(self):
        """
        Print certificate contents to stdout
        """
        return plain.Zcert.print_(self)

    def fprint(self, file):
        """
        DEPRECATED as incompatible with centralized logging
Print certificate contents to open stream
        """
        return plain.Zcert.fprint(self, file)

    @staticmethod
    def test(verbose):
        """
        Self test of this class
        """
        return plain.Zcert.test(verbose)



class Zcertstore(plain.Zcertstore):
    def __init__(self, *args, **kw):
        """
        Create a new certificate store from a disk directory, loading and
indexing all certificates in that location. The directory itself may be
absent, and created later, or modified at any time. The certificate store
is automatically refreshed on any zcertstore_lookup() call. If the
location is specified as NULL, creates a pure-memory store, which you
can work with by inserting certificates at runtime.
        """
        plain.Zcertstore.__init__(*args, **kw)

    def lookup(self, public_key):
        """
        Look up certificate by public key, returns zcert_t object if found,
else returns NULL. The public key is provided in Z85 text format.
        """
        return plain.Zcertstore.lookup(self, public_key)

    def insert(self, cert_p):
        """
        Insert certificate into certificate store in memory. Note that this
does not save the certificate to disk. To do that, use zcert_save()
directly on the certificate. Takes ownership of zcert_t object.
        """
        return plain.Zcertstore.insert(self, cert_p)

    def print_(self):
        """
        Print list of certificates in store to logging facility
        """
        return plain.Zcertstore.print_(self)

    def fprint(self, file):
        """
        DEPRECATED as incompatible with centralized logging
Print list of certificates in store to open stream
        """
        return plain.Zcertstore.fprint(self, file)

    @staticmethod
    def test(verbose):
        """
        Self test of this class
        """
        return plain.Zcertstore.test(verbose)



class Zchunk(plain.Zchunk):
    def __init__(self, *args, **kw):
        """
        Create a new chunk of the specified size. If you specify the data, it
is copied into the chunk. If you do not specify the data, the chunk is
allocated and left empty, and you can then add data using zchunk_append.
        """
        plain.Zchunk.__init__(*args, **kw)

    def resize(self, size):
        """
        Resizes chunk max_size as requested; chunk_cur size is set to zero
        """
        return plain.Zchunk.resize(self, size)

    def size(self):
        """
        Return chunk cur size
        """
        return plain.Zchunk.size(self)

    def max_size(self):
        """
        Return chunk max size
        """
        return plain.Zchunk.max_size(self)

    def data(self):
        """
        Return chunk data
        """
        return plain.Zchunk.data(self)

    def set(self, data, size):
        """
        Set chunk data from user-supplied data; truncate if too large. Data may
be null. Returns actual size of chunk
        """
        return plain.Zchunk.set(self, data, size)

    def fill(self, filler, size):
        """
        Fill chunk data from user-supplied octet
        """
        return plain.Zchunk.fill(self, filler, size)

    def append(self, data, size):
        """
        Append user-supplied data to chunk, return resulting chunk size. If the
data would exceeded the available space, it is truncated. If you want to
grow the chunk to accommodate new data, use the zchunk_extend method.
        """
        return plain.Zchunk.append(self, data, size)

    def extend(self, data, size):
        """
        Append user-supplied data to chunk, return resulting chunk size. If the
data would exceeded the available space, the chunk grows in size.
        """
        return plain.Zchunk.extend(self, data, size)

    def consume(self, source):
        """
        Copy as much data from 'source' into the chunk as possible; returns the
new size of chunk. If all data from 'source' is used, returns exhausted
on the source chunk. Source can be consumed as many times as needed until
it is exhausted. If source was already exhausted, does not change chunk.
        """
        return plain.Zchunk.consume(self, source)

    def exhausted(self):
        """
        Returns true if the chunk was exhausted by consume methods, or if the
chunk has a size of zero.
        """
        return plain.Zchunk.exhausted(self)

    @staticmethod
    def read(handle, bytes):
        """
        Read chunk from an open file descriptor
        """
        return plain.Zchunk.read(handle, bytes)

    def write(self, handle):
        """
        Write chunk to an open file descriptor
        """
        return plain.Zchunk.write(self, handle)

    @staticmethod
    def slurp(filename, maxsize):
        """
        Try to slurp an entire file into a chunk. Will read up to maxsize of
the file. If maxsize is 0, will attempt to read the entire file and
fail with an assertion if that cannot fit into memory. Returns a new
chunk containing the file data, or NULL if the file could not be read.
        """
        return plain.Zchunk.slurp(filename, maxsize)

    def dup(self):
        """
        Create copy of chunk, as new chunk object. Returns a fresh zchunk_t
object, or null if there was not enough heap memory. If chunk is null,
returns null.
        """
        return plain.Zchunk.dup(self)

    def strhex(self):
        """
        Return chunk data encoded as printable hex string. Caller must free
string when finished with it.
        """
        return plain.Zchunk.strhex(self)

    def strdup(self):
        """
        Return chunk data copied into freshly allocated string
Caller must free string when finished with it.
        """
        return plain.Zchunk.strdup(self)

    def streq(self, string):
        """
        Return TRUE if chunk body is equal to string, excluding terminator
        """
        return plain.Zchunk.streq(self, string)

    def pack(self):
        """
        Transform zchunk into a zframe that can be sent in a message.
        """
        return plain.Zchunk.pack(self)

    @staticmethod
    def unpack(frame):
        """
        Transform a zframe into a zchunk.
        """
        return plain.Zchunk.unpack(frame)

    def digest(self):
        """
        Calculate SHA1 digest for chunk, using zdigest class.
        """
        return plain.Zchunk.digest(self)

    def fprint(self, file):
        """
        Dump chunk to FILE stream, for debugging and tracing.
        """
        return plain.Zchunk.fprint(self, file)

    def print_(self):
        """
        Dump message to stderr, for debugging and tracing.
See zchunk_fprint for details
        """
        return plain.Zchunk.print_(self)

    @staticmethod
    def is_(self):
        """
        Probe the supplied object, and report if it looks like a zchunk_t.
        """
        return plain.Zchunk.is_(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zchunk.test(verbose)



class Zclock(plain.Zclock):
    @staticmethod
    def sleep(msecs):
        """
        Sleep for a number of milliseconds
        """
        return plain.Zclock.sleep(msecs)

    @staticmethod
    def time():
        """
        Return current system clock as milliseconds. Note that this clock can
jump backwards (if the system clock is changed) so is unsafe to use for
timers and time offsets. Use zclock_mono for that instead.
        """
        return plain.Zclock.time()

    @staticmethod
    def mono():
        """
        Return current monotonic clock in milliseconds. Use this when you compute
time offsets. The monotonic clock is not affected by system changes and
so will never be reset backwards, unlike a system clock.
        """
        return plain.Zclock.mono()

    @staticmethod
    def usecs():
        """
        Return current monotonic clock in microseconds. Use this when you compute
time offsets. The monotonic clock is not affected by system changes and
so will never be reset backwards, unlike a system clock.
        """
        return plain.Zclock.usecs()

    @staticmethod
    def timestr():
        """
        Return formatted date/time as fresh string. Free using zstr_free().
        """
        return plain.Zclock.timestr()

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zclock.test(verbose)



class Zconfig(plain.Zconfig):
    def __init__(self, *args, **kw):
        """
        Create new config item
        """
        plain.Zconfig.__init__(*args, **kw)

    @staticmethod
    def load(filename):
        """
        Load a config tree from a specified ZPL text file; returns a zconfig_t
reference for the root, if the file exists and is readable. Returns NULL
if the file does not exist.
        """
        return plain.Zconfig.load(filename)

    @staticmethod
    def loadf(format, *args):
        """
        Equivalent to zconfig_load, taking a format string instead of a fixed
filename.
        """
        return plain.Zconfig.loadf(format, *args)

    def name(self):
        """
        Return name of config item
        """
        return plain.Zconfig.name(self)

    def value(self):
        """
        Return value of config item
        """
        return plain.Zconfig.value(self)

    def put(self, path, value):
        """
        Insert or update configuration key with value
        """
        return plain.Zconfig.put(self, path, value)

    def putf(self, path, format, *args):
        """
        Equivalent to zconfig_put, accepting a format specifier and variable
argument list, instead of a single string value.
        """
        return plain.Zconfig.putf(self, path, format, *args)

    def get(self, path, default_value):
        """
        Get value for config item into a string value; leading slash is optional
and ignored.
        """
        return plain.Zconfig.get(self, path, default_value)

    def set_name(self, name):
        """
        Set config item name, name may be NULL
        """
        return plain.Zconfig.set_name(self, name)

    def set_value(self, format, *args):
        """
        Set new value for config item. The new value may be a string, a printf
format, or NULL. Note that if string may possibly contain '%', or if it
comes from an insecure source, you must use '%s' as the format, followed
by the string.
        """
        return plain.Zconfig.set_value(self, format, *args)

    def child(self):
        """
        Find our first child, if any
        """
        return plain.Zconfig.child(self)

    def next(self):
        """
        Find our first sibling, if any
        """
        return plain.Zconfig.next(self)

    def locate(self, path):
        """
        Find a config item along a path; leading slash is optional and ignored.
        """
        return plain.Zconfig.locate(self, path)

    def at_depth(self, level):
        """
        Locate the last config item at a specified depth
        """
        return plain.Zconfig.at_depth(self, level)

    def execute(self, handler, arg):
        """
        Execute a callback for each config item in the tree; returns zero if
successful, else -1.
        """
        return plain.Zconfig.execute(self, handler, arg)

    def set_comment(self, format, *args):
        """
        Add comment to config item before saving to disk. You can add as many
comment lines as you like. If you use a null format, all comments are
deleted.
        """
        return plain.Zconfig.set_comment(self, format, *args)

    def comments(self):
        """
        Return comments of config item, as zlist.
        """
        return plain.Zconfig.comments(self)

    def save(self, filename):
        """
        Save a config tree to a specified ZPL text file, where a filename
"-" means dump to standard output.
        """
        return plain.Zconfig.save(self, filename)

    def savef(self, format, *args):
        """
        Equivalent to zconfig_save, taking a format string instead of a fixed
filename.
        """
        return plain.Zconfig.savef(self, format, *args)

    def filename(self):
        """
        Report filename used during zconfig_load, or NULL if none
        """
        return plain.Zconfig.filename(self)

    @staticmethod
    def reload(self_p):
        """
        Reload config tree from same file that it was previously loaded from.
Returns 0 if OK, -1 if there was an error (and then does not change
existing data).
        """
        return plain.Zconfig.reload(self_p)

    @staticmethod
    def chunk_load(chunk):
        """
        Load a config tree from a memory chunk
        """
        return plain.Zconfig.chunk_load(chunk)

    def chunk_save(self):
        """
        Save a config tree to a new memory chunk
        """
        return plain.Zconfig.chunk_save(self)

    @staticmethod
    def str_load(string):
        """
        Load a config tree from a null-terminated string
        """
        return plain.Zconfig.str_load(string)

    def str_save(self):
        """
        Save a config tree to a new null terminated string
        """
        return plain.Zconfig.str_save(self)

    def has_changed(self):
        """
        Return true if a configuration tree was loaded from a file and that
file has changed in since the tree was loaded.
        """
        return plain.Zconfig.has_changed(self)

    def fprint(self, file):
        """
        Print the config file to open stream
        """
        return plain.Zconfig.fprint(self, file)

    def print_(self):
        """
        Print properties of object
        """
        return plain.Zconfig.print_(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class
        """
        return plain.Zconfig.test(verbose)



class Zdigest(plain.Zdigest):
    def __init__(self, *args, **kw):
        """
        Constructor - creates new digest object, which you use to build up a
digest by repeatedly calling zdigest_update() on chunks of data.
        """
        plain.Zdigest.__init__(*args, **kw)

    def update(self, buffer, length):
        """
        Add buffer into digest calculation
        """
        return plain.Zdigest.update(self, buffer, length)

    def data(self):
        """
        Return final digest hash data. If built without crypto support, returns
NULL.
        """
        return plain.Zdigest.data(self)

    def size(self):
        """
        Return final digest hash size
        """
        return plain.Zdigest.size(self)

    def string(self):
        """
        Return digest as printable hex string; caller should not modify nor
free this string. After calling this, you may not use zdigest_update()
on the same digest. If built without crypto support, returns NULL.
        """
        return plain.Zdigest.string(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zdigest.test(verbose)



class Zdir(plain.Zdir):
    def __init__(self, *args, **kw):
        """
        Create a new directory item that loads in the full tree of the specified
path, optionally located under some parent path. If parent is "-", then
loads only the top-level directory, and does not use parent as a path.
        """
        plain.Zdir.__init__(*args, **kw)

    def path(self):
        """
        Return directory path
        """
        return plain.Zdir.path(self)

    def modified(self):
        """
        Return last modification time for directory.
        """
        return plain.Zdir.modified(self)

    def cursize(self):
        """
        Return total hierarchy size, in bytes of data contained in all files
in the directory tree.
        """
        return plain.Zdir.cursize(self)

    def count(self):
        """
        Return directory count
        """
        return plain.Zdir.count(self)

    def list(self):
        """
        Returns a sorted list of zfile objects; Each entry in the list is a pointer
to a zfile_t item already allocated in the zdir tree. Do not destroy the
original zdir tree until you are done with this list.
        """
        return plain.Zdir.list(self)

    def remove(self, force):
        """
        Remove directory, optionally including all files that it contains, at
all levels. If force is false, will only remove the directory if empty.
If force is true, will remove all files and all subdirectories.
        """
        return plain.Zdir.remove(self, force)

    @staticmethod
    def diff(older, newer, alias):
        """
        Calculate differences between two versions of a directory tree.
Returns a list of zdir_patch_t patches. Either older or newer may
be null, indicating the directory is empty/absent. If alias is set,
generates virtual filename (minus path, plus alias).
        """
        return plain.Zdir.diff(older, newer, alias)

    def resync(self, alias):
        """
        Return full contents of directory as a zdir_patch list.
        """
        return plain.Zdir.resync(self, alias)

    def cache(self):
        """
        Load directory cache; returns a hash table containing the SHA-1 digests
of every file in the tree. The cache is saved between runs in .cache.
        """
        return plain.Zdir.cache(self)

    def fprint(self, file, indent):
        """
        Print contents of directory to open stream
        """
        return plain.Zdir.fprint(self, file, indent)

    def print_(self, indent):
        """
        Print contents of directory to stdout
        """
        return plain.Zdir.print_(self, indent)

    @staticmethod
    def watch(pipe, unused):
        """
        Create a new zdir_watch actor instance:

    zactor_t *watch = zactor_new (zdir_watch, NULL);

Destroy zdir_watch instance:

    zactor_destroy (&watch);

Enable verbose logging of commands and activity:

    zstr_send (watch, "VERBOSE");

Subscribe to changes to a directory path:

    zsock_send (watch, "ss", "SUBSCRIBE", "directory_path");

Unsubscribe from changes to a directory path:

    zsock_send (watch, "ss", "UNSUBSCRIBE", "directory_path");

Receive directory changes:
    zsock_recv (watch, "sp", &path, &patches);

    // Delete the received data.
    free (path);
    zlist_destroy (&patches);
        """
        return plain.Zdir.watch(pipe, unused)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zdir.test(verbose)



class ZdirPatch(plain.ZdirPatch):
    def __init__(self, *args, **kw):
        """
        Create new patch
        """
        plain.ZdirPatch.__init__(*args, **kw)

    def dup(self):
        """
        Create copy of a patch. If the patch is null, or memory was exhausted,
returns null.
        """
        return plain.ZdirPatch.dup(self)

    def path(self):
        """
        Return patch file directory path
        """
        return plain.ZdirPatch.path(self)

    def file(self):
        """
        Return patch file item
        """
        return plain.ZdirPatch.file(self)

    def op(self):
        """
        Return operation
        """
        return plain.ZdirPatch.op(self)

    def vpath(self):
        """
        Return patch virtual file path
        """
        return plain.ZdirPatch.vpath(self)

    def digest_set(self):
        """
        Calculate hash digest for file (create only)
        """
        return plain.ZdirPatch.digest_set(self)

    def digest(self):
        """
        Return hash digest for patch file
        """
        return plain.ZdirPatch.digest(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.ZdirPatch.test(verbose)



class Zfile(plain.Zfile):
    def __init__(self, *args, **kw):
        """
        If file exists, populates properties. CZMQ supports portable symbolic
links, which are files with the extension ".ln". A symbolic link is a
text file containing one line, the filename of a target file. Reading
data from the symbolic link actually reads from the target file. Path
may be NULL, in which case it is not used.
        """
        plain.Zfile.__init__(*args, **kw)

    def dup(self):
        """
        Duplicate a file item, returns a newly constructed item. If the file
is null, or memory was exhausted, returns null.
        """
        return plain.Zfile.dup(self)

    def filename(self, path):
        """
        Return file name, remove path if provided
        """
        return plain.Zfile.filename(self, path)

    def restat(self):
        """
        Refresh file properties from disk; this is not done automatically
on access methods, otherwise it is not possible to compare directory
snapshots.
        """
        return plain.Zfile.restat(self)

    def modified(self):
        """
        Return when the file was last modified. If you want this to reflect the
current situation, call zfile_restat before checking this property.
        """
        return plain.Zfile.modified(self)

    def cursize(self):
        """
        Return the last-known size of the file. If you want this to reflect the
current situation, call zfile_restat before checking this property.
        """
        return plain.Zfile.cursize(self)

    def is_directory(self):
        """
        Return true if the file is a directory. If you want this to reflect
any external changes, call zfile_restat before checking this property.
        """
        return plain.Zfile.is_directory(self)

    def is_regular(self):
        """
        Return true if the file is a regular file. If you want this to reflect
any external changes, call zfile_restat before checking this property.
        """
        return plain.Zfile.is_regular(self)

    def is_readable(self):
        """
        Return true if the file is readable by this process. If you want this to
reflect any external changes, call zfile_restat before checking this
property.
        """
        return plain.Zfile.is_readable(self)

    def is_writeable(self):
        """
        Return true if the file is writeable by this process. If you want this
to reflect any external changes, call zfile_restat before checking this
property.
        """
        return plain.Zfile.is_writeable(self)

    def is_stable(self):
        """
        Check if file has stopped changing and can be safely processed.
Updates the file statistics from disk at every call.
        """
        return plain.Zfile.is_stable(self)

    def has_changed(self):
        """
        Return true if the file was changed on disk since the zfile_t object
was created, or the last zfile_restat() call made on it.
        """
        return plain.Zfile.has_changed(self)

    def remove(self):
        """
        Remove the file from disk
        """
        return plain.Zfile.remove(self)

    def input(self):
        """
        Open file for reading
Returns 0 if OK, -1 if not found or not accessible
        """
        return plain.Zfile.input(self)

    def output(self):
        """
        Open file for writing, creating directory if needed
File is created if necessary; chunks can be written to file at any
location. Returns 0 if OK, -1 if error.
        """
        return plain.Zfile.output(self)

    def read(self, bytes, offset):
        """
        Read chunk from file at specified position. If this was the last chunk,
sets the eof property. Returns a null chunk in case of error.
        """
        return plain.Zfile.read(self, bytes, offset)

    def eof(self):
        """
        Returns true if zfile_read() just read the last chunk in the file.
        """
        return plain.Zfile.eof(self)

    def write(self, chunk, offset):
        """
        Write chunk to file at specified position
Return 0 if OK, else -1
        """
        return plain.Zfile.write(self, chunk, offset)

    def readln(self):
        """
        Read next line of text from file. Returns a pointer to the text line,
or NULL if there was nothing more to read from the file.
        """
        return plain.Zfile.readln(self)

    def close(self):
        """
        Close file, if open
        """
        return plain.Zfile.close(self)

    def handle(self):
        """
        Return file handle, if opened
        """
        return plain.Zfile.handle(self)

    def digest(self):
        """
        Calculate SHA1 digest for file, using zdigest class.
        """
        return plain.Zfile.digest(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zfile.test(verbose)



class Zframe(plain.Zframe):
    def __init__(self, *args, **kw):
        """
        Create a new frame. If size is not null, allocates the frame data
to the specified size. If additionally, data is not null, copies
size octets from the specified data into the frame body.
        """
        plain.Zframe.__init__(*args, **kw)

    @staticmethod
    def new_empty():
        """
        Create an empty (zero-sized) frame
        """
        return plain.Zframe.new_empty()

    @staticmethod
    def from_(string):
        """
        Create a frame with a specified string content.
        """
        return plain.Zframe.from_(string)

    @staticmethod
    def recv(source):
        """
        Receive frame from socket, returns zframe_t object or NULL if the recv
was interrupted. Does a blocking recv, if you want to not block then use
zpoller or zloop.
        """
        return plain.Zframe.recv(source)

    @staticmethod
    def send(self_p, dest, flags):
        """
        Send a frame to a socket, destroy frame after sending.
Return -1 on error, 0 on success.
        """
        return plain.Zframe.send(self_p, dest, flags)

    def size(self):
        """
        Return number of bytes in frame data
        """
        return plain.Zframe.size(self)

    def data(self):
        """
        Return address of frame data
        """
        return plain.Zframe.data(self)

    def dup(self):
        """
        Create a new frame that duplicates an existing frame. If frame is null,
or memory was exhausted, returns null.
        """
        return plain.Zframe.dup(self)

    def strhex(self):
        """
        Return frame data encoded as printable hex string, useful for 0MQ UUIDs.
Caller must free string when finished with it.
        """
        return plain.Zframe.strhex(self)

    def strdup(self):
        """
        Return frame data copied into freshly allocated string
Caller must free string when finished with it.
        """
        return plain.Zframe.strdup(self)

    def streq(self, string):
        """
        Return TRUE if frame body is equal to string, excluding terminator
        """
        return plain.Zframe.streq(self, string)

    def more(self):
        """
        Return frame MORE indicator (1 or 0), set when reading frame from socket
or by the zframe_set_more() method
        """
        return plain.Zframe.more(self)

    def set_more(self, more):
        """
        Set frame MORE indicator (1 or 0). Note this is NOT used when sending
frame to socket, you have to specify flag explicitly.
        """
        return plain.Zframe.set_more(self, more)

    def routing_id(self):
        """
        Return frame routing ID, if the frame came from a ZMQ_SERVER socket.
Else returns zero.
        """
        return plain.Zframe.routing_id(self)

    def set_routing_id(self, routing_id):
        """
        Set routing ID on frame. This is used if/when the frame is sent to a
ZMQ_SERVER socket.
        """
        return plain.Zframe.set_routing_id(self, routing_id)

    def group(self):
        """
        Return frame group of radio-dish pattern.
        """
        return plain.Zframe.group(self)

    def set_group(self, group):
        """
        Set group on frame. This is used if/when the frame is sent to a
ZMQ_RADIO socket.
Return -1 on error, 0 on success.
        """
        return plain.Zframe.set_group(self, group)

    def eq(self, other):
        """
        Return TRUE if two frames have identical size and data
If either frame is NULL, equality is always false.
        """
        return plain.Zframe.eq(self, other)

    def reset(self, data, size):
        """
        Set new contents for frame
        """
        return plain.Zframe.reset(self, data, size)

    def print_(self, prefix):
        """
        Send message to zsys log sink (may be stdout, or system facility as
configured by zsys_set_logstream). Prefix shows before frame, if not null.
        """
        return plain.Zframe.print_(self, prefix)

    @staticmethod
    def is_(self):
        """
        Probe the supplied object, and report if it looks like a zframe_t.
        """
        return plain.Zframe.is_(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zframe.test(verbose)



class Zhash(plain.Zhash):
    def __init__(self, *args, **kw):
        """
        Create a new, empty hash container
        """
        plain.Zhash.__init__(*args, **kw)

    @staticmethod
    def unpack(frame):
        """
        Unpack binary frame into a new hash table. Packed data must follow format
defined by zhash_pack. Hash table is set to autofree. An empty frame
unpacks to an empty hash table.
        """
        return plain.Zhash.unpack(frame)

    def insert(self, key, item):
        """
        Insert item into hash table with specified key and item.
If key is already present returns -1 and leaves existing item unchanged
Returns 0 on success.
        """
        return plain.Zhash.insert(self, key, item)

    def update(self, key, item):
        """
        Update item into hash table with specified key and item.
If key is already present, destroys old item and inserts new one.
Use free_fn method to ensure deallocator is properly called on item.
        """
        return plain.Zhash.update(self, key, item)

    def delete(self, key):
        """
        Remove an item specified by key from the hash table. If there was no such
item, this function does nothing.
        """
        return plain.Zhash.delete(self, key)

    def lookup(self, key):
        """
        Return the item at the specified key, or null
        """
        return plain.Zhash.lookup(self, key)

    def rename(self, old_key, new_key):
        """
        Reindexes an item from an old key to a new key. If there was no such
item, does nothing. Returns 0 if successful, else -1.
        """
        return plain.Zhash.rename(self, old_key, new_key)

    def freefn(self, key, free_fn):
        """
        Set a free function for the specified hash table item. When the item is
destroyed, the free function, if any, is called on that item.
Use this when hash items are dynamically allocated, to ensure that
you don't have memory leaks. You can pass 'free' or NULL as a free_fn.
Returns the item, or NULL if there is no such item.
        """
        return plain.Zhash.freefn(self, key, free_fn)

    def size(self):
        """
        Return the number of keys/items in the hash table
        """
        return plain.Zhash.size(self)

    def dup(self):
        """
        Make copy of hash table; if supplied table is null, returns null.
Does not copy items themselves. Rebuilds new table so may be slow on
very large tables. NOTE: only works with item values that are strings
since there's no other way to know how to duplicate the item value.
        """
        return plain.Zhash.dup(self)

    def keys(self):
        """
        Return keys for items in table
        """
        return plain.Zhash.keys(self)

    def first(self):
        """
        Simple iterator; returns first item in hash table, in no given order,
or NULL if the table is empty. This method is simpler to use than the
foreach() method, which is deprecated. To access the key for this item
use zhash_cursor(). NOTE: do NOT modify the table while iterating.
        """
        return plain.Zhash.first(self)

    def next(self):
        """
        Simple iterator; returns next item in hash table, in no given order,
or NULL if the last item was already returned. Use this together with
zhash_first() to process all items in a hash table. If you need the
items in sorted order, use zhash_keys() and then zlist_sort(). To
access the key for this item use zhash_cursor(). NOTE: do NOT modify
the table while iterating.
        """
        return plain.Zhash.next(self)

    def cursor(self):
        """
        After a successful first/next method, returns the key for the item that
was returned. This is a constant string that you may not modify or
deallocate, and which lasts as long as the item in the hash. After an
unsuccessful first/next, returns NULL.
        """
        return plain.Zhash.cursor(self)

    def comment(self, format, *args):
        """
        Add a comment to hash table before saving to disk. You can add as many
comment lines as you like. These comment lines are discarded when loading
the file. If you use a null format, all comments are deleted.
        """
        return plain.Zhash.comment(self, format, *args)

    def pack(self):
        """
        Serialize hash table to a binary frame that can be sent in a message.
The packed format is compatible with the 'dictionary' type defined in
http://rfc.zeromq.org/spec:35/FILEMQ, and implemented by zproto:

   ; A list of name/value pairs
   dictionary      = dict-count *( dict-name dict-value )
   dict-count      = number-4
   dict-value      = longstr
   dict-name       = string

   ; Strings are always length + text contents
   longstr         = number-4 *VCHAR
   string          = number-1 *VCHAR

   ; Numbers are unsigned integers in network byte order
   number-1        = 1OCTET
   number-4        = 4OCTET

Comments are not included in the packed data. Item values MUST be
strings.
        """
        return plain.Zhash.pack(self)

    def save(self, filename):
        """
        Save hash table to a text file in name=value format. Hash values must be
printable strings; keys may not contain '=' character. Returns 0 if OK,
else -1 if a file error occurred.
        """
        return plain.Zhash.save(self, filename)

    def load(self, filename):
        """
        Load hash table from a text file in name=value format; hash table must
already exist. Hash values must printable strings; keys may not contain
'=' character. Returns 0 if OK, else -1 if a file was not readable.
        """
        return plain.Zhash.load(self, filename)

    def refresh(self):
        """
        When a hash table was loaded from a file by zhash_load, this method will
reload the file if it has been modified since, and is "stable", i.e. not
still changing. Returns 0 if OK, -1 if there was an error reloading the 
file.
        """
        return plain.Zhash.refresh(self)

    def autofree(self):
        """
        Set hash for automatic value destruction
        """
        return plain.Zhash.autofree(self)

    def foreach(self, callback, argument):
        """
        Apply function to each item in the hash table. Items are iterated in no
defined order. Stops if callback function returns non-zero and returns
final return code from callback function (zero = success). Deprecated.
        """
        return plain.Zhash.foreach(self, callback, argument)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zhash.test(verbose)



class Zhashx(plain.Zhashx):
    def __init__(self, *args, **kw):
        """
        Create a new, empty hash container
        """
        plain.Zhashx.__init__(*args, **kw)

    @staticmethod
    def unpack(frame):
        """
        Unpack binary frame into a new hash table. Packed data must follow format
defined by zhashx_pack. Hash table is set to autofree. An empty frame
unpacks to an empty hash table.
        """
        return plain.Zhashx.unpack(frame)

    def insert(self, key, item):
        """
        Insert item into hash table with specified key and item.
If key is already present returns -1 and leaves existing item unchanged
Returns 0 on success.
        """
        return plain.Zhashx.insert(self, key, item)

    def update(self, key, item):
        """
        Update or insert item into hash table with specified key and item. If the
key is already present, destroys old item and inserts new one. If you set
a container item destructor, this is called on the old value. If the key
was not already present, inserts a new item. Sets the hash cursor to the
new item.
        """
        return plain.Zhashx.update(self, key, item)

    def delete(self, key):
        """
        Remove an item specified by key from the hash table. If there was no such
item, this function does nothing.
        """
        return plain.Zhashx.delete(self, key)

    def purge(self):
        """
        Delete all items from the hash table. If the key destructor is
set, calls it on every key. If the item destructor is set, calls
it on every item.
        """
        return plain.Zhashx.purge(self)

    def lookup(self, key):
        """
        Return the item at the specified key, or null
        """
        return plain.Zhashx.lookup(self, key)

    def rename(self, old_key, new_key):
        """
        Reindexes an item from an old key to a new key. If there was no such
item, does nothing. Returns 0 if successful, else -1.
        """
        return plain.Zhashx.rename(self, old_key, new_key)

    def freefn(self, key, free_fn):
        """
        Set a free function for the specified hash table item. When the item is
destroyed, the free function, if any, is called on that item.
Use this when hash items are dynamically allocated, to ensure that
you don't have memory leaks. You can pass 'free' or NULL as a free_fn.
Returns the item, or NULL if there is no such item.
        """
        return plain.Zhashx.freefn(self, key, free_fn)

    def size(self):
        """
        Return the number of keys/items in the hash table
        """
        return plain.Zhashx.size(self)

    def keys(self):
        """
        Return a zlistx_t containing the keys for the items in the
table. Uses the key_duplicator to duplicate all keys and sets the
key_destructor as destructor for the list.
        """
        return plain.Zhashx.keys(self)

    def values(self):
        """
        Return a zlistx_t containing the values for the items in the
table. Uses the duplicator to duplicate all items and sets the
destructor as destructor for the list.
        """
        return plain.Zhashx.values(self)

    def first(self):
        """
        Simple iterator; returns first item in hash table, in no given order,
or NULL if the table is empty. This method is simpler to use than the
foreach() method, which is deprecated. To access the key for this item
use zhashx_cursor(). NOTE: do NOT modify the table while iterating.
        """
        return plain.Zhashx.first(self)

    def next(self):
        """
        Simple iterator; returns next item in hash table, in no given order,
or NULL if the last item was already returned. Use this together with
zhashx_first() to process all items in a hash table. If you need the
items in sorted order, use zhashx_keys() and then zlistx_sort(). To
access the key for this item use zhashx_cursor(). NOTE: do NOT modify
the table while iterating.
        """
        return plain.Zhashx.next(self)

    def cursor(self):
        """
        After a successful first/next method, returns the key for the item that
was returned. This is a constant string that you may not modify or
deallocate, and which lasts as long as the item in the hash. After an
unsuccessful first/next, returns NULL.
        """
        return plain.Zhashx.cursor(self)

    def comment(self, format, *args):
        """
        Add a comment to hash table before saving to disk. You can add as many
comment lines as you like. These comment lines are discarded when loading
the file. If you use a null format, all comments are deleted.
        """
        return plain.Zhashx.comment(self, format, *args)

    def save(self, filename):
        """
        Save hash table to a text file in name=value format. Hash values must be
printable strings; keys may not contain '=' character. Returns 0 if OK,
else -1 if a file error occurred.
        """
        return plain.Zhashx.save(self, filename)

    def load(self, filename):
        """
        Load hash table from a text file in name=value format; hash table must
already exist. Hash values must printable strings; keys may not contain
'=' character. Returns 0 if OK, else -1 if a file was not readable.
        """
        return plain.Zhashx.load(self, filename)

    def refresh(self):
        """
        When a hash table was loaded from a file by zhashx_load, this method will
reload the file if it has been modified since, and is "stable", i.e. not
still changing. Returns 0 if OK, -1 if there was an error reloading the 
file.
        """
        return plain.Zhashx.refresh(self)

    def pack(self):
        """
        Serialize hash table to a binary frame that can be sent in a message.
The packed format is compatible with the 'dictionary' type defined in
http://rfc.zeromq.org/spec:35/FILEMQ, and implemented by zproto:

   ; A list of name/value pairs
   dictionary      = dict-count *( dict-name dict-value )
   dict-count      = number-4
   dict-value      = longstr
   dict-name       = string

   ; Strings are always length + text contents
   longstr         = number-4 *VCHAR
   string          = number-1 *VCHAR

   ; Numbers are unsigned integers in network byte order
   number-1        = 1OCTET
   number-4        = 4OCTET

Comments are not included in the packed data. Item values MUST be
strings.
        """
        return plain.Zhashx.pack(self)

    def dup(self):
        """
        Make a copy of the list; items are duplicated if you set a duplicator
for the list, otherwise not. Copying a null reference returns a null
reference. Note that this method's behavior changed slightly for CZMQ
v3.x, as it does not set nor respect autofree. It does however let you
duplicate any hash table safely. The old behavior is in zhashx_dup_v2.
        """
        return plain.Zhashx.dup(self)

    def set_destructor(self, destructor):
        """
        Set a user-defined deallocator for hash items; by default items are not
freed when the hash is destroyed.
        """
        return plain.Zhashx.set_destructor(self, destructor)

    def set_duplicator(self, duplicator):
        """
        Set a user-defined duplicator for hash items; by default items are not
copied when the hash is duplicated.
        """
        return plain.Zhashx.set_duplicator(self, duplicator)

    def set_key_destructor(self, destructor):
        """
        Set a user-defined deallocator for keys; by default keys are freed
when the hash is destroyed using free().
        """
        return plain.Zhashx.set_key_destructor(self, destructor)

    def set_key_duplicator(self, duplicator):
        """
        Set a user-defined duplicator for keys; by default keys are duplicated
using strdup.
        """
        return plain.Zhashx.set_key_duplicator(self, duplicator)

    def set_key_comparator(self, comparator):
        """
        Set a user-defined comparator for keys; by default keys are
compared using strcmp.
        """
        return plain.Zhashx.set_key_comparator(self, comparator)

    def set_key_hasher(self, hasher):
        """
        Set a user-defined comparator for keys; by default keys are
compared using strcmp.
        """
        return plain.Zhashx.set_key_hasher(self, hasher)

    def dup_v2(self):
        """
        Make copy of hash table; if supplied table is null, returns null.
Does not copy items themselves. Rebuilds new table so may be slow on
very large tables. NOTE: only works with item values that are strings
since there's no other way to know how to duplicate the item value.
        """
        return plain.Zhashx.dup_v2(self)

    def autofree(self):
        """
        DEPRECATED as clumsy -- use set_destructor instead
Set hash for automatic value destruction
        """
        return plain.Zhashx.autofree(self)

    def foreach(self, callback, argument):
        """
        DEPRECATED as clumsy -- use zhashx_first/_next instead
Apply function to each item in the hash table. Items are iterated in no
defined order. Stops if callback function returns non-zero and returns
final return code from callback function (zero = success).
Callback function for zhashx_foreach method
        """
        return plain.Zhashx.foreach(self, callback, argument)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zhashx.test(verbose)



class Ziflist(plain.Ziflist):
    def __init__(self, *args, **kw):
        """
        Get a list of network interfaces currently defined on the system
        """
        plain.Ziflist.__init__(*args, **kw)

    def reload(self):
        """
        Reload network interfaces from system
        """
        return plain.Ziflist.reload(self)

    def size(self):
        """
        Return the number of network interfaces on system
        """
        return plain.Ziflist.size(self)

    def first(self):
        """
        Get first network interface, return NULL if there are none
        """
        return plain.Ziflist.first(self)

    def next(self):
        """
        Get next network interface, return NULL if we hit the last one
        """
        return plain.Ziflist.next(self)

    def address(self):
        """
        Return the current interface IP address as a printable string
        """
        return plain.Ziflist.address(self)

    def broadcast(self):
        """
        Return the current interface broadcast address as a printable string
        """
        return plain.Ziflist.broadcast(self)

    def netmask(self):
        """
        Return the current interface network mask as a printable string
        """
        return plain.Ziflist.netmask(self)

    def print_(self):
        """
        Return the list of interfaces.
        """
        return plain.Ziflist.print_(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Ziflist.test(verbose)



class Zlist(plain.Zlist):
    def __init__(self, *args, **kw):
        """
        Create a new list container
        """
        plain.Zlist.__init__(*args, **kw)

    def first(self):
        """
        Return the item at the head of list. If the list is empty, returns NULL.
Leaves cursor pointing at the head item, or NULL if the list is empty.
        """
        return plain.Zlist.first(self)

    def next(self):
        """
        Return the next item. If the list is empty, returns NULL. To move to
the start of the list call zlist_first (). Advances the cursor.
        """
        return plain.Zlist.next(self)

    def last(self):
        """
        Return the item at the tail of list. If the list is empty, returns NULL.
Leaves cursor pointing at the tail item, or NULL if the list is empty.
        """
        return plain.Zlist.last(self)

    def head(self):
        """
        Return first item in the list, or null, leaves the cursor
        """
        return plain.Zlist.head(self)

    def tail(self):
        """
        Return last item in the list, or null, leaves the cursor
        """
        return plain.Zlist.tail(self)

    def item(self):
        """
        Return the current item of list. If the list is empty, returns NULL.
Leaves cursor pointing at the current item, or NULL if the list is empty.
        """
        return plain.Zlist.item(self)

    def append(self, item):
        """
        Append an item to the end of the list, return 0 if OK or -1 if this
failed for some reason (out of memory). Note that if a duplicator has
been set, this method will also duplicate the item.
        """
        return plain.Zlist.append(self, item)

    def push(self, item):
        """
        Push an item to the start of the list, return 0 if OK or -1 if this
failed for some reason (out of memory). Note that if a duplicator has
been set, this method will also duplicate the item.
        """
        return plain.Zlist.push(self, item)

    def pop(self):
        """
        Pop the item off the start of the list, if any
        """
        return plain.Zlist.pop(self)

    def exists(self, item):
        """
        Checks if an item already is present. Uses compare method to determine if
items are equal. If the compare method is NULL the check will only compare
pointers. Returns true if item is present else false.
        """
        return plain.Zlist.exists(self, item)

    def remove(self, item):
        """
        Remove the specified item from the list if present
        """
        return plain.Zlist.remove(self, item)

    def dup(self):
        """
        Make a copy of list. If the list has autofree set, the copied list will
duplicate all items, which must be strings. Otherwise, the list will hold
pointers back to the items in the original list. If list is null, returns
NULL.
        """
        return plain.Zlist.dup(self)

    def purge(self):
        """
        Purge all items from list
        """
        return plain.Zlist.purge(self)

    def size(self):
        """
        Return number of items in the list
        """
        return plain.Zlist.size(self)

    def sort(self, compare):
        """
        Sort the list by ascending key value using a straight ASCII comparison.
The sort is not stable, so may reorder items with the same keys.
        """
        return plain.Zlist.sort(self, compare)

    def autofree(self):
        """
        Set list for automatic item destruction; item values MUST be strings.
By default a list item refers to a value held elsewhere. When you set
this, each time you append or push a list item, zlist will take a copy
of the string value. Then, when you destroy the list, it will free all
item values automatically. If you use any other technique to allocate
list values, you must free them explicitly before destroying the list.
The usual technique is to pop list items and destroy them, until the
list is empty.
        """
        return plain.Zlist.autofree(self)

    def comparefn(self, fn):
        """
        Sets a compare function for this list. The function compares two items.
It returns an integer less than, equal to, or greater than zero if the
first item is found, respectively, to be less than, to match, or be
greater than the second item.
This function is used for sorting, removal and exists checking.
        """
        return plain.Zlist.comparefn(self, fn)

    def freefn(self, item, fn, at_tail):
        """
        Set a free function for the specified list item. When the item is
destroyed, the free function, if any, is called on that item.
Use this when list items are dynamically allocated, to ensure that
you don't have memory leaks. You can pass 'free' or NULL as a free_fn.
Returns the item, or NULL if there is no such item.
        """
        return plain.Zlist.freefn(self, item, fn, at_tail)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zlist.test(verbose)



class Zlistx(plain.Zlistx):
    def __init__(self, *args, **kw):
        """
        Create a new, empty list.
        """
        plain.Zlistx.__init__(*args, **kw)

    def add_start(self, item):
        """
        Add an item to the head of the list. Calls the item duplicator, if any,
on the item. Resets cursor to list head. Returns an item handle on
success, NULL if memory was exhausted.
        """
        return plain.Zlistx.add_start(self, item)

    def add_end(self, item):
        """
        Add an item to the tail of the list. Calls the item duplicator, if any,
on the item. Resets cursor to list head. Returns an item handle on
success, NULL if memory was exhausted.
        """
        return plain.Zlistx.add_end(self, item)

    def size(self):
        """
        Return the number of items in the list
        """
        return plain.Zlistx.size(self)

    def head(self):
        """
        Return first item in the list, or null, leaves the cursor
        """
        return plain.Zlistx.head(self)

    def tail(self):
        """
        Return last item in the list, or null, leaves the cursor
        """
        return plain.Zlistx.tail(self)

    def first(self):
        """
        Return the item at the head of list. If the list is empty, returns NULL.
Leaves cursor pointing at the head item, or NULL if the list is empty.
        """
        return plain.Zlistx.first(self)

    def next(self):
        """
        Return the next item. At the end of the list (or in an empty list),
returns NULL. Use repeated zlistx_next () calls to work through the list
from zlistx_first (). First time, acts as zlistx_first().
        """
        return plain.Zlistx.next(self)

    def prev(self):
        """
        Return the previous item. At the start of the list (or in an empty list),
returns NULL. Use repeated zlistx_prev () calls to work through the list
backwards from zlistx_last (). First time, acts as zlistx_last().
        """
        return plain.Zlistx.prev(self)

    def last(self):
        """
        Return the item at the tail of list. If the list is empty, returns NULL.
Leaves cursor pointing at the tail item, or NULL if the list is empty.
        """
        return plain.Zlistx.last(self)

    def item(self):
        """
        Returns the value of the item at the cursor, or NULL if the cursor is
not pointing to an item.
        """
        return plain.Zlistx.item(self)

    def cursor(self):
        """
        Returns the handle of the item at the cursor, or NULL if the cursor is
not pointing to an item.
        """
        return plain.Zlistx.cursor(self)

    @staticmethod
    def handle_item(handle):
        """
        Returns the item associated with the given list handle, or NULL if passed
in handle is NULL. Asserts that the passed in handle points to a list element.
        """
        return plain.Zlistx.handle_item(handle)

    def find(self, item):
        """
        Find an item in the list, searching from the start. Uses the item
comparator, if any, else compares item values directly. Returns the
item handle found, or NULL. Sets the cursor to the found item, if any.
        """
        return plain.Zlistx.find(self, item)

    def detach(self, handle):
        """
        Detach an item from the list, using its handle. The item is not modified,
and the caller is responsible for destroying it if necessary. If handle is
null, detaches the first item on the list. Returns item that was detached,
or null if none was. If cursor was at item, moves cursor to previous item,
so you can detach items while iterating forwards through a list.
        """
        return plain.Zlistx.detach(self, handle)

    def detach_cur(self):
        """
        Detach item at the cursor, if any, from the list. The item is not modified,
and the caller is responsible for destroying it as necessary. Returns item
that was detached, or null if none was. Moves cursor to previous item, so
you can detach items while iterating forwards through a list.
        """
        return plain.Zlistx.detach_cur(self)

    def delete(self, handle):
        """
        Delete an item, using its handle. Calls the item destructor is any is
set. If handle is null, deletes the first item on the list. Returns 0
if an item was deleted, -1 if not. If cursor was at item, moves cursor
to previous item, so you can delete items while iterating forwards
through a list.
        """
        return plain.Zlistx.delete(self, handle)

    def move_start(self, handle):
        """
        Move an item to the start of the list, via its handle.
        """
        return plain.Zlistx.move_start(self, handle)

    def move_end(self, handle):
        """
        Move an item to the end of the list, via its handle.
        """
        return plain.Zlistx.move_end(self, handle)

    def purge(self):
        """
        Remove all items from the list, and destroy them if the item destructor
is set.
        """
        return plain.Zlistx.purge(self)

    def sort(self):
        """
        Sort the list. If an item comparator was set, calls that to compare
items, otherwise compares on item value. The sort is not stable, so may
reorder equal items.
        """
        return plain.Zlistx.sort(self)

    def insert(self, item, low_value):
        """
        Create a new node and insert it into a sorted list. Calls the item
duplicator, if any, on the item. If low_value is true, starts searching
from the start of the list, otherwise searches from the end. Use the item
comparator, if any, to find where to place the new node. Returns a handle
to the new node, or NULL if memory was exhausted. Resets the cursor to the
list head.
        """
        return plain.Zlistx.insert(self, item, low_value)

    def reorder(self, handle, low_value):
        """
        Move an item, specified by handle, into position in a sorted list. Uses
the item comparator, if any, to determine the new location. If low_value
is true, starts searching from the start of the list, otherwise searches
from the end.
        """
        return plain.Zlistx.reorder(self, handle, low_value)

    def dup(self):
        """
        Make a copy of the list; items are duplicated if you set a duplicator
for the list, otherwise not. Copying a null reference returns a null
reference.
        """
        return plain.Zlistx.dup(self)

    def set_destructor(self, destructor):
        """
        Set a user-defined deallocator for list items; by default items are not
freed when the list is destroyed.
        """
        return plain.Zlistx.set_destructor(self, destructor)

    def set_duplicator(self, duplicator):
        """
        Set a user-defined duplicator for list items; by default items are not
copied when the list is duplicated.
        """
        return plain.Zlistx.set_duplicator(self, duplicator)

    def set_comparator(self, comparator):
        """
        Set a user-defined comparator for zlistx_find and zlistx_sort; the method
must return -1, 0, or 1 depending on whether item1 is less than, equal to,
or greater than, item2.
        """
        return plain.Zlistx.set_comparator(self, comparator)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zlistx.test(verbose)



class Zloop(plain.Zloop):
    def __init__(self, *args, **kw):
        """
        Create a new zloop reactor
        """
        plain.Zloop.__init__(*args, **kw)

    def reader(self, sock, handler, arg):
        """
        Register socket reader with the reactor. When the reader has messages,
the reactor will call the handler, passing the arg. Returns 0 if OK, -1
if there was an error. If you register the same socket more than once,
each instance will invoke its corresponding handler.
        """
        return plain.Zloop.reader(self, sock, handler, arg)

    def reader_end(self, sock):
        """
        Cancel a socket reader from the reactor. If multiple readers exist for
same socket, cancels ALL of them.
        """
        return plain.Zloop.reader_end(self, sock)

    def reader_set_tolerant(self, sock):
        """
        Configure a registered reader to ignore errors. If you do not set this,
then readers that have errors are removed from the reactor silently.
        """
        return plain.Zloop.reader_set_tolerant(self, sock)

    def poller(self, item, handler, arg):
        """
        Register low-level libzmq pollitem with the reactor. When the pollitem
is ready, will call the handler, passing the arg. Returns 0 if OK, -1
if there was an error. If you register the pollitem more than once, each
instance will invoke its corresponding handler. A pollitem with
socket=NULL and fd=0 means 'poll on FD zero'.
        """
        return plain.Zloop.poller(self, item, handler, arg)

    def poller_end(self, item):
        """
        Cancel a pollitem from the reactor, specified by socket or FD. If both
are specified, uses only socket. If multiple poll items exist for same
socket/FD, cancels ALL of them.
        """
        return plain.Zloop.poller_end(self, item)

    def poller_set_tolerant(self, item):
        """
        Configure a registered poller to ignore errors. If you do not set this,
then poller that have errors are removed from the reactor silently.
        """
        return plain.Zloop.poller_set_tolerant(self, item)

    def timer(self, delay, times, handler, arg):
        """
        Register a timer that expires after some delay and repeats some number of
times. At each expiry, will call the handler, passing the arg. To run a
timer forever, use 0 times. Returns a timer_id that is used to cancel the
timer in the future. Returns -1 if there was an error.
        """
        return plain.Zloop.timer(self, delay, times, handler, arg)

    def timer_end(self, timer_id):
        """
        Cancel a specific timer identified by a specific timer_id (as returned by
zloop_timer).
        """
        return plain.Zloop.timer_end(self, timer_id)

    def ticket(self, handler, arg):
        """
        Register a ticket timer. Ticket timers are very fast in the case where
you use a lot of timers (thousands), and frequently remove and add them.
The main use case is expiry timers for servers that handle many clients,
and which reset the expiry timer for each message received from a client.
Whereas normal timers perform poorly as the number of clients grows, the
cost of ticket timers is constant, no matter the number of clients. You
must set the ticket delay using zloop_set_ticket_delay before creating a
ticket. Returns a handle to the timer that you should use in
zloop_ticket_reset and zloop_ticket_delete.
        """
        return plain.Zloop.ticket(self, handler, arg)

    def ticket_reset(self, handle):
        """
        Reset a ticket timer, which moves it to the end of the ticket list and
resets its execution time. This is a very fast operation.
        """
        return plain.Zloop.ticket_reset(self, handle)

    def ticket_delete(self, handle):
        """
        Delete a ticket timer. We do not actually delete the ticket here, as
other code may still refer to the ticket. We mark as deleted, and remove
later and safely.
        """
        return plain.Zloop.ticket_delete(self, handle)

    def set_ticket_delay(self, ticket_delay):
        """
        Set the ticket delay, which applies to all tickets. If you lower the
delay and there are already tickets created, the results are undefined.
        """
        return plain.Zloop.set_ticket_delay(self, ticket_delay)

    def set_max_timers(self, max_timers):
        """
        Set hard limit on number of timers allowed. Setting more than a small
number of timers (10-100) can have a dramatic impact on the performance
of the reactor. For high-volume cases, use ticket timers. If the hard
limit is reached, the reactor stops creating new timers and logs an
error.
        """
        return plain.Zloop.set_max_timers(self, max_timers)

    def set_verbose(self, verbose):
        """
        Set verbose tracing of reactor on/off. The default verbose setting is
off (false).
        """
        return plain.Zloop.set_verbose(self, verbose)

    def set_nonstop(self, nonstop):
        """
        By default the reactor stops if the process receives a SIGINT or SIGTERM
signal. This makes it impossible to shut-down message based architectures
like zactors. This method lets you switch off break handling. The default
nonstop setting is off (false).
        """
        return plain.Zloop.set_nonstop(self, nonstop)

    def start(self):
        """
        Start the reactor. Takes control of the thread and returns when the 0MQ
context is terminated or the process is interrupted, or any event handler
returns -1. Event handlers may register new sockets and timers, and
cancel sockets. Returns 0 if interrupted, -1 if canceled by a handler.
        """
        return plain.Zloop.start(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zloop.test(verbose)



class Zmsg(plain.Zmsg):
    def __init__(self, *args, **kw):
        """
        Create a new empty message object
        """
        plain.Zmsg.__init__(*args, **kw)

    @staticmethod
    def recv(source):
        """
        Receive message from socket, returns zmsg_t object or NULL if the recv
was interrupted. Does a blocking recv. If you want to not block then use
the zloop class or zmsg_recv_nowait or zmq_poll to check for socket input
before receiving.
        """
        return plain.Zmsg.recv(source)

    @staticmethod
    def load(file):
        """
        Load/append an open file into new message, return the message.
Returns NULL if the message could not be loaded.
        """
        return plain.Zmsg.load(file)

    @staticmethod
    def decode(buffer, buffer_size):
        """
        Decodes a serialized message buffer created by zmsg_encode () and returns
a new zmsg_t object. Returns NULL if the buffer was badly formatted or
there was insufficient memory to work.
        """
        return plain.Zmsg.decode(buffer, buffer_size)

    @staticmethod
    def new_signal(status):
        """
        Generate a signal message encoding the given status. A signal is a short
message carrying a 1-byte success/failure code (by convention, 0 means
OK). Signals are encoded to be distinguishable from "normal" messages.
        """
        return plain.Zmsg.new_signal(status)

    @staticmethod
    def send(self_p, dest):
        """
        Send message to destination socket, and destroy the message after sending
it successfully. If the message has no frames, sends nothing but destroys
the message anyhow. Nullifies the caller's reference to the message (as
it is a destructor).
        """
        return plain.Zmsg.send(self_p, dest)

    @staticmethod
    def sendm(self_p, dest):
        """
        Send message to destination socket as part of a multipart sequence, and
destroy the message after sending it successfully. Note that after a
zmsg_sendm, you must call zmsg_send or another method that sends a final
message part. If the message has no frames, sends nothing but destroys
the message anyhow. Nullifies the caller's reference to the message (as
it is a destructor).
        """
        return plain.Zmsg.sendm(self_p, dest)

    def size(self):
        """
        Return size of message, i.e. number of frames (0 or more).
        """
        return plain.Zmsg.size(self)

    def content_size(self):
        """
        Return total size of all frames in message.
        """
        return plain.Zmsg.content_size(self)

    def routing_id(self):
        """
        Return message routing ID, if the message came from a ZMQ_SERVER socket.
Else returns zero.
        """
        return plain.Zmsg.routing_id(self)

    def set_routing_id(self, routing_id):
        """
        Set routing ID on message. This is used if/when the message is sent to a
ZMQ_SERVER socket.
        """
        return plain.Zmsg.set_routing_id(self, routing_id)

    def prepend(self, frame_p):
        """
        Push frame to the front of the message, i.e. before all other frames.
Message takes ownership of frame, will destroy it when message is sent.
Returns 0 on success, -1 on error. Deprecates zmsg_push, which did not
nullify the caller's frame reference.
        """
        return plain.Zmsg.prepend(self, frame_p)

    def append(self, frame_p):
        """
        Add frame to the end of the message, i.e. after all other frames.
Message takes ownership of frame, will destroy it when message is sent.
Returns 0 on success. Deprecates zmsg_add, which did not nullify the
caller's frame reference.
        """
        return plain.Zmsg.append(self, frame_p)

    def pop(self):
        """
        Remove first frame from message, if any. Returns frame, or NULL.
        """
        return plain.Zmsg.pop(self)

    def pushmem(self, src, size):
        """
        Push block of memory to front of message, as a new frame.
Returns 0 on success, -1 on error.
        """
        return plain.Zmsg.pushmem(self, src, size)

    def addmem(self, src, size):
        """
        Add block of memory to the end of the message, as a new frame.
Returns 0 on success, -1 on error.
        """
        return plain.Zmsg.addmem(self, src, size)

    def pushstr(self, string):
        """
        Push string as new frame to front of message.
Returns 0 on success, -1 on error.
        """
        return plain.Zmsg.pushstr(self, string)

    def addstr(self, string):
        """
        Push string as new frame to end of message.
Returns 0 on success, -1 on error.
        """
        return plain.Zmsg.addstr(self, string)

    def pushstrf(self, format, *args):
        """
        Push formatted string as new frame to front of message.
Returns 0 on success, -1 on error.
        """
        return plain.Zmsg.pushstrf(self, format, *args)

    def addstrf(self, format, *args):
        """
        Push formatted string as new frame to end of message.
Returns 0 on success, -1 on error.
        """
        return plain.Zmsg.addstrf(self, format, *args)

    def popstr(self):
        """
        Pop frame off front of message, return as fresh string. If there were
no more frames in the message, returns NULL.
        """
        return plain.Zmsg.popstr(self)

    def addmsg(self, msg_p):
        """
        Push encoded message as a new frame. Message takes ownership of
submessage, so the original is destroyed in this call. Returns 0 on
success, -1 on error.
        """
        return plain.Zmsg.addmsg(self, msg_p)

    def popmsg(self):
        """
        Remove first submessage from message, if any. Returns zmsg_t, or NULL if
decoding was not succesful.
        """
        return plain.Zmsg.popmsg(self)

    def remove(self, frame):
        """
        Remove specified frame from list, if present. Does not destroy frame.
        """
        return plain.Zmsg.remove(self, frame)

    def first(self):
        """
        Set cursor to first frame in message. Returns frame, or NULL, if the
message is empty. Use this to navigate the frames as a list.
        """
        return plain.Zmsg.first(self)

    def next(self):
        """
        Return the next frame. If there are no more frames, returns NULL. To move
to the first frame call zmsg_first(). Advances the cursor.
        """
        return plain.Zmsg.next(self)

    def last(self):
        """
        Return the last frame. If there are no frames, returns NULL.
        """
        return plain.Zmsg.last(self)

    def save(self, file):
        """
        Save message to an open file, return 0 if OK, else -1. The message is
saved as a series of frames, each with length and data. Note that the
file is NOT guaranteed to be portable between operating systems, not
versions of CZMQ. The file format is at present undocumented and liable
to arbitrary change.
        """
        return plain.Zmsg.save(self, file)

    def encode(self, buffer):
        """
        Serialize multipart message to a single buffer. Use this method to send
structured messages across transports that do not support multipart data.
Allocates and returns a new buffer containing the serialized message.
To decode a serialized message buffer, use zmsg_decode ().
        """
        return plain.Zmsg.encode(self, buffer)

    def dup(self):
        """
        Create copy of message, as new message object. Returns a fresh zmsg_t
object. If message is null, or memory was exhausted, returns null.
        """
        return plain.Zmsg.dup(self)

    def print_(self):
        """
        Send message to zsys log sink (may be stdout, or system facility as
configured by zsys_set_logstream).
        """
        return plain.Zmsg.print_(self)

    def eq(self, other):
        """
        Return true if the two messages have the same number of frames and each
frame in the first message is identical to the corresponding frame in the
other message. As with zframe_eq, return false if either message is NULL.
        """
        return plain.Zmsg.eq(self, other)

    def signal(self):
        """
        Return signal value, 0 or greater, if message is a signal, -1 if not.
        """
        return plain.Zmsg.signal(self)

    @staticmethod
    def is_(self):
        """
        Probe the supplied object, and report if it looks like a zmsg_t.
        """
        return plain.Zmsg.is_(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zmsg.test(verbose)



class Zpoller(plain.Zpoller):
    def __init__(self, *args, **kw):
        """
        Create new poller, specifying zero or more readers. The list of
readers ends in a NULL. Each reader can be a zsock_t instance, a
zactor_t instance, a libzmq socket (void *), or a file handle.
        """
        plain.Zpoller.__init__(*args, **kw)

    def add(self, reader):
        """
        Add a reader to be polled. Returns 0 if OK, -1 on failure. The reader may
be a libzmq void * socket, a zsock_t instance, or a zactor_t instance.
        """
        return plain.Zpoller.add(self, reader)

    def remove(self, reader):
        """
        Remove a reader from the poller; returns 0 if OK, -1 on failure. The reader
must have been passed during construction, or in an zpoller_add () call.
        """
        return plain.Zpoller.remove(self, reader)

    def set_nonstop(self, nonstop):
        """
        By default the poller stops if the process receives a SIGINT or SIGTERM
signal. This makes it impossible to shut-down message based architectures
like zactors. This method lets you switch off break handling. The default
nonstop setting is off (false).
        """
        return plain.Zpoller.set_nonstop(self, nonstop)

    def wait(self, timeout):
        """
        Poll the registered readers for I/O, return first reader that has input.
The reader will be a libzmq void * socket, or a zsock_t or zactor_t
instance as specified in zpoller_new/zpoller_add. The timeout should be
zero or greater, or -1 to wait indefinitely. Socket priority is defined
by their order in the poll list. If you need a balanced poll, use the low
level zmq_poll method directly. If the poll call was interrupted (SIGINT),
or the ZMQ context was destroyed, or the timeout expired, returns NULL.
You can test the actual exit condition by calling zpoller_expired () and
zpoller_terminated (). The timeout is in msec.
        """
        return plain.Zpoller.wait(self, timeout)

    def expired(self):
        """
        Return true if the last zpoller_wait () call ended because the timeout
expired, without any error.
        """
        return plain.Zpoller.expired(self)

    def terminated(self):
        """
        Return true if the last zpoller_wait () call ended because the process
was interrupted, or the parent context was destroyed.
        """
        return plain.Zpoller.terminated(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zpoller.test(verbose)



class Zproc(plain.Zproc):
    @staticmethod
    def czmq_version():
        """
        Returns CZMQ version as a single 6-digit integer encoding the major
version (x 10000), the minor version (x 100) and the patch.
        """
        return plain.Zproc.czmq_version()

    @staticmethod
    def interrupted():
        """
        Returns true if the process received a SIGINT or SIGTERM signal.
It is good practice to use this method to exit any infinite loop
processing messages.
        """
        return plain.Zproc.interrupted()

    @staticmethod
    def has_curve():
        """
        Returns true if the underlying libzmq supports CURVE security.
        """
        return plain.Zproc.has_curve()

    @staticmethod
    def hostname():
        """
        Return current host name, for use in public tcp:// endpoints.
If the host name is not resolvable, returns NULL.
        """
        return plain.Zproc.hostname()

    @staticmethod
    def daemonize(workdir):
        """
        Move the current process into the background. The precise effect
depends on the operating system. On POSIX boxes, moves to a specified
working directory (if specified), closes all file handles, reopens
stdin, stdout, and stderr to the null device, and sets the process to
ignore SIGHUP. On Windows, does nothing. Returns 0 if OK, -1 if there
was an error.
        """
        return plain.Zproc.daemonize(workdir)

    @staticmethod
    def run_as(lockfile, group, user):
        """
        Drop the process ID into the lockfile, with exclusive lock, and
switch the process to the specified group and/or user. Any of the
arguments may be null, indicating a no-op. Returns 0 on success,
-1 on failure. Note if you combine this with zsys_daemonize, run
after, not before that method, or the lockfile will hold the wrong
process ID.
        """
        return plain.Zproc.run_as(lockfile, group, user)

    @staticmethod
    def set_io_threads(io_threads):
        """
        Configure the number of I/O threads that ZeroMQ will use. A good
rule of thumb is one thread per gigabit of traffic in or out. The
default is 1, sufficient for most applications. If the environment
variable ZSYS_IO_THREADS is defined, that provides the default.
Note that this method is valid only before any socket is created.
        """
        return plain.Zproc.set_io_threads(io_threads)

    @staticmethod
    def set_max_sockets(max_sockets):
        """
        Configure the number of sockets that ZeroMQ will allow. The default
is 1024. The actual limit depends on the system, and you can query it
by using zsys_socket_limit (). A value of zero means "maximum".
Note that this method is valid only before any socket is created.
        """
        return plain.Zproc.set_max_sockets(max_sockets)

    @staticmethod
    def set_biface(value):
        """
        Set network interface name to use for broadcasts, particularly zbeacon.
This lets the interface be configured for test environments where required.
For example, on Mac OS X, zbeacon cannot bind to 255.255.255.255 which is
the default when there is no specified interface. If the environment
variable ZSYS_INTERFACE is set, use that as the default interface name.
Setting the interface to "*" means "use all available interfaces".
        """
        return plain.Zproc.set_biface(value)

    @staticmethod
    def biface():
        """
        Return network interface to use for broadcasts, or "" if none was set.
        """
        return plain.Zproc.biface()

    @staticmethod
    def set_log_ident(value):
        """
        Set log identity, which is a string that prefixes all log messages sent
by this process. The log identity defaults to the environment variable
ZSYS_LOGIDENT, if that is set.
        """
        return plain.Zproc.set_log_ident(value)

    @staticmethod
    def set_log_sender(endpoint):
        """
        Sends log output to a PUB socket bound to the specified endpoint. To
collect such log output, create a SUB socket, subscribe to the traffic
you care about, and connect to the endpoint. Log traffic is sent as a
single string frame, in the same format as when sent to stdout. The
log system supports a single sender; multiple calls to this method will
bind the same sender to multiple endpoints. To disable the sender, call
this method with a null argument.
        """
        return plain.Zproc.set_log_sender(endpoint)

    @staticmethod
    def set_log_system(logsystem):
        """
        Enable or disable logging to the system facility (syslog on POSIX boxes,
event log on Windows). By default this is disabled.
        """
        return plain.Zproc.set_log_system(logsystem)

    @staticmethod
    def log_error(format, *args):
        """
        Log error condition - highest priority
        """
        return plain.Zproc.log_error(format, *args)

    @staticmethod
    def log_warning(format, *args):
        """
        Log warning condition - high priority
        """
        return plain.Zproc.log_warning(format, *args)

    @staticmethod
    def log_notice(format, *args):
        """
        Log normal, but significant, condition - normal priority
        """
        return plain.Zproc.log_notice(format, *args)

    @staticmethod
    def log_info(format, *args):
        """
        Log informational message - low priority
        """
        return plain.Zproc.log_info(format, *args)

    @staticmethod
    def log_debug(format, *args):
        """
        Log debug-level message - lowest priority
        """
        return plain.Zproc.log_debug(format, *args)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zproc.test(verbose)



class Zsock(plain.Zsock):
    def __init__(self, *args, **kw):
        """
        Create a new socket. Returns the new socket, or NULL if the new socket
could not be created. Note that the symbol zsock_new (and other
constructors/destructors for zsock) are redirected to the *_checked
variant, enabling intelligent socket leak detection. This can have
performance implications if you use a LOT of sockets. To turn off this
redirection behaviour, define ZSOCK_NOCHECK.
        """
        plain.Zsock.__init__(*args, **kw)

    @staticmethod
    def new_pub(endpoint):
        """
        Create a PUB socket. Default action is bind.
        """
        return plain.Zsock.new_pub(endpoint)

    @staticmethod
    def new_sub(endpoint, subscribe):
        """
        Create a SUB socket, and optionally subscribe to some prefix string. Default
action is connect.
        """
        return plain.Zsock.new_sub(endpoint, subscribe)

    @staticmethod
    def new_req(endpoint):
        """
        Create a REQ socket. Default action is connect.
        """
        return plain.Zsock.new_req(endpoint)

    @staticmethod
    def new_rep(endpoint):
        """
        Create a REP socket. Default action is bind.
        """
        return plain.Zsock.new_rep(endpoint)

    @staticmethod
    def new_dealer(endpoint):
        """
        Create a DEALER socket. Default action is connect.
        """
        return plain.Zsock.new_dealer(endpoint)

    @staticmethod
    def new_router(endpoint):
        """
        Create a ROUTER socket. Default action is bind.
        """
        return plain.Zsock.new_router(endpoint)

    @staticmethod
    def new_push(endpoint):
        """
        Create a PUSH socket. Default action is connect.
        """
        return plain.Zsock.new_push(endpoint)

    @staticmethod
    def new_pull(endpoint):
        """
        Create a PULL socket. Default action is bind.
        """
        return plain.Zsock.new_pull(endpoint)

    @staticmethod
    def new_xpub(endpoint):
        """
        Create an XPUB socket. Default action is bind.
        """
        return plain.Zsock.new_xpub(endpoint)

    @staticmethod
    def new_xsub(endpoint):
        """
        Create an XSUB socket. Default action is connect.
        """
        return plain.Zsock.new_xsub(endpoint)

    @staticmethod
    def new_pair(endpoint):
        """
        Create a PAIR socket. Default action is connect.
        """
        return plain.Zsock.new_pair(endpoint)

    @staticmethod
    def new_stream(endpoint):
        """
        Create a STREAM socket. Default action is connect.
        """
        return plain.Zsock.new_stream(endpoint)

    @staticmethod
    def new_server(endpoint):
        """
        Create a SERVER socket. Default action is bind.
        """
        return plain.Zsock.new_server(endpoint)

    @staticmethod
    def new_client(endpoint):
        """
        Create a CLIENT socket. Default action is connect.
        """
        return plain.Zsock.new_client(endpoint)

    @staticmethod
    def new_radio(endpoint):
        """
        Create a RADIO socket. Default action is bind.
        """
        return plain.Zsock.new_radio(endpoint)

    @staticmethod
    def new_dish(endpoint):
        """
        Create a DISH socket. Default action is connect.
        """
        return plain.Zsock.new_dish(endpoint)

    def bind(self, format, *args):
        """
        Bind a socket to a formatted endpoint. For tcp:// endpoints, supports
ephemeral ports, if you specify the port number as "*". By default
zsock uses the IANA designated range from C000 (49152) to FFFF (65535).
To override this range, follow the "*" with "[first-last]". Either or
both first and last may be empty. To bind to a random port within the
range, use "!" in place of "*".

Examples:
    tcp://127.0.0.1:*           bind to first free port from C000 up
    tcp://127.0.0.1:!           bind to random port from C000 to FFFF
    tcp://127.0.0.1:*[60000-]   bind to first free port from 60000 up
    tcp://127.0.0.1:![-60000]   bind to random port from C000 to 60000
    tcp://127.0.0.1:![55000-55999]
                                bind to random port from 55000 to 55999

On success, returns the actual port number used, for tcp:// endpoints,
and 0 for other transports. On failure, returns -1. Note that when using
ephemeral ports, a port may be reused by different services without
clients being aware. Protocols that run on ephemeral ports should take
this into account.
        """
        return plain.Zsock.bind(self, format, *args)

    def endpoint(self):
        """
        Returns last bound endpoint, if any.
        """
        return plain.Zsock.endpoint(self)

    def unbind(self, format, *args):
        """
        Unbind a socket from a formatted endpoint.
Returns 0 if OK, -1 if the endpoint was invalid or the function
isn't supported.
        """
        return plain.Zsock.unbind(self, format, *args)

    def connect(self, format, *args):
        """
        Connect a socket to a formatted endpoint
Returns 0 if OK, -1 if the endpoint was invalid.
        """
        return plain.Zsock.connect(self, format, *args)

    def disconnect(self, format, *args):
        """
        Disconnect a socket from a formatted endpoint
Returns 0 if OK, -1 if the endpoint was invalid or the function
isn't supported.
        """
        return plain.Zsock.disconnect(self, format, *args)

    def attach(self, endpoints, serverish):
        """
        Attach a socket to zero or more endpoints. If endpoints is not null,
parses as list of ZeroMQ endpoints, separated by commas, and prefixed by
'@' (to bind the socket) or '>' (to connect the socket). Returns 0 if all
endpoints were valid, or -1 if there was a syntax error. If the endpoint
does not start with '@' or '>', the serverish argument defines whether
it is used to bind (serverish = true) or connect (serverish = false).
        """
        return plain.Zsock.attach(self, endpoints, serverish)

    def type_str(self):
        """
        Returns socket type as printable constant string.
        """
        return plain.Zsock.type_str(self)

    def send(self, picture, *args):
        """
        Send a 'picture' message to the socket (or actor). The picture is a
string that defines the type of each frame. This makes it easy to send
a complex multiframe message in one call. The picture can contain any
of these characters, each corresponding to one or two arguments:

    i = int (signed)
    1 = uint8_t
    2 = uint16_t
    4 = uint32_t
    8 = uint64_t
    s = char *
    b = byte *, size_t (2 arguments)
    c = zchunk_t *
    f = zframe_t *
    h = zhashx_t *
    U = zuuid_t *
    p = void * (sends the pointer value, only meaningful over inproc)
    m = zmsg_t * (sends all frames in the zmsg)
    z = sends zero-sized frame (0 arguments)
    u = uint (deprecated)

Note that s, b, c, and f are encoded the same way and the choice is
offered as a convenience to the sender, which may or may not already
have data in a zchunk or zframe. Does not change or take ownership of
any arguments. Returns 0 if successful, -1 if sending failed for any
reason.
        """
        return plain.Zsock.send(self, picture, *args)

    def vsend(self, picture, argptr):
        """
        Send a 'picture' message to the socket (or actor). This is a va_list
version of zsock_send (), so please consult its documentation for the
details.
        """
        return plain.Zsock.vsend(self, picture, argptr)

    def recv(self, picture, *args):
        """
        Receive a 'picture' message to the socket (or actor). See zsock_send for
the format and meaning of the picture. Returns the picture elements into
a series of pointers as provided by the caller:

    i = int * (stores signed integer)
    4 = uint32_t * (stores 32-bit unsigned integer)
    8 = uint64_t * (stores 64-bit unsigned integer)
    s = char ** (allocates new string)
    b = byte **, size_t * (2 arguments) (allocates memory)
    c = zchunk_t ** (creates zchunk)
    f = zframe_t ** (creates zframe)
    U = zuuid_t * (creates a zuuid with the data)
    h = zhashx_t ** (creates zhashx)
    p = void ** (stores pointer)
    m = zmsg_t ** (creates a zmsg with the remaing frames)
    z = null, asserts empty frame (0 arguments)
    u = uint * (stores unsigned integer, deprecated)

Note that zsock_recv creates the returned objects, and the caller must
destroy them when finished with them. The supplied pointers do not need
to be initialized. Returns 0 if successful, or -1 if it failed to recv
a message, in which case the pointers are not modified. When message
frames are truncated (a short message), sets return values to zero/null.
If an argument pointer is NULL, does not store any value (skips it).
An 'n' picture matches an empty frame; if the message does not match,
the method will return -1.
        """
        return plain.Zsock.recv(self, picture, *args)

    def vrecv(self, picture, argptr):
        """
        Receive a 'picture' message from the socket (or actor). This is a
va_list version of zsock_recv (), so please consult its documentation
for the details.
        """
        return plain.Zsock.vrecv(self, picture, argptr)

    def bsend(self, picture, *args):
        """
        Send a binary encoded 'picture' message to the socket (or actor). This
method is similar to zsock_send, except the arguments are encoded in a
binary format that is compatible with zproto, and is designed to reduce
memory allocations. The pattern argument is a string that defines the
type of each argument. Supports these argument types:

 pattern    C type                  zproto type:
    1       uint8_t                 type = "number" size = "1"
    2       uint16_t                type = "number" size = "2"
    4       uint32_t                type = "number" size = "3"
    8       uint64_t                type = "number" size = "4"
    s       char *, 0-255 chars     type = "string"
    S       char *, 0-2^32-1 chars  type = "longstr"
    c       zchunk_t *              type = "chunk"
    f       zframe_t *              type = "frame"
    u       zuuid_t *               type = "uuid"
    m       zmsg_t *                type = "msg"
    p       void *, sends pointer value, only over inproc

Does not change or take ownership of any arguments. Returns 0 if
successful, -1 if sending failed for any reason.
        """
        return plain.Zsock.bsend(self, picture, *args)

    def brecv(self, picture, *args):
        """
        Receive a binary encoded 'picture' message from the socket (or actor).
This method is similar to zsock_recv, except the arguments are encoded
in a binary format that is compatible with zproto, and is designed to
reduce memory allocations. The pattern argument is a string that defines
the type of each argument. See zsock_bsend for the supported argument
types. All arguments must be pointers; this call sets them to point to
values held on a per-socket basis.
Note that zsock_brecv creates the returned objects, and the caller must
destroy them when finished with them. The supplied pointers do not need
to be initialized. Returns 0 if successful, or -1 if it failed to read
a message.
        """
        return plain.Zsock.brecv(self, picture, *args)

    def routing_id(self):
        """
        Return socket routing ID if any. This returns 0 if the socket is not
of type ZMQ_SERVER or if no request was already received on it.
        """
        return plain.Zsock.routing_id(self)

    def set_routing_id(self, routing_id):
        """
        Set routing ID on socket. The socket MUST be of type ZMQ_SERVER.
This will be used when sending messages on the socket via the zsock API.
        """
        return plain.Zsock.set_routing_id(self, routing_id)

    def set_unbounded(self):
        """
        Set socket to use unbounded pipes (HWM=0); use this in cases when you are
totally certain the message volume can fit in memory. This method works
across all versions of ZeroMQ. Takes a polymorphic socket reference.
        """
        return plain.Zsock.set_unbounded(self)

    def signal(self, status):
        """
        Send a signal over a socket. A signal is a short message carrying a
success/failure code (by convention, 0 means OK). Signals are encoded
to be distinguishable from "normal" messages. Accepts a zsock_t or a
zactor_t argument, and returns 0 if successful, -1 if the signal could
not be sent. Takes a polymorphic socket reference.
        """
        return plain.Zsock.signal(self, status)

    def wait(self):
        """
        Wait on a signal. Use this to coordinate between threads, over pipe
pairs. Blocks until the signal is received. Returns -1 on error, 0 or
greater on success. Accepts a zsock_t or a zactor_t as argument.
Takes a polymorphic socket reference.
        """
        return plain.Zsock.wait(self)

    def flush(self):
        """
        If there is a partial message still waiting on the socket, remove and
discard it. This is useful when reading partial messages, to get specific
message types.
        """
        return plain.Zsock.flush(self)

    def join(self, group):
        """
        Join a group for the RADIO-DISH pattern. Call only on ZMQ_DISH.
Returns 0 if OK, -1 if failed.
        """
        return plain.Zsock.join(self, group)

    def leave(self, group):
        """
        Leave a group for the RADIO-DISH pattern. Call only on ZMQ_DISH.
Returns 0 if OK, -1 if failed.
        """
        return plain.Zsock.leave(self, group)

    @staticmethod
    def is_(self):
        """
        Probe the supplied object, and report if it looks like a zsock_t.
Takes a polymorphic socket reference.
        """
        return plain.Zsock.is_(self)

    @staticmethod
    def resolve(self):
        """
        Probe the supplied reference. If it looks like a zsock_t instance, return
the underlying libzmq socket handle; else if it looks like a file
descriptor, return NULL; else if it looks like a libzmq socket handle,
return the supplied value. Takes a polymorphic socket reference.
        """
        return plain.Zsock.resolve(self)

    def heartbeat_ivl(self):
        """
        Get socket option `heartbeat_ivl`.
        """
        return plain.Zsock.heartbeat_ivl(self)

    def set_heartbeat_ivl(self, heartbeat_ivl):
        """
        Set socket option `heartbeat_ivl`.
        """
        return plain.Zsock.set_heartbeat_ivl(self, heartbeat_ivl)

    def heartbeat_ttl(self):
        """
        Get socket option `heartbeat_ttl`.
        """
        return plain.Zsock.heartbeat_ttl(self)

    def set_heartbeat_ttl(self, heartbeat_ttl):
        """
        Set socket option `heartbeat_ttl`.
        """
        return plain.Zsock.set_heartbeat_ttl(self, heartbeat_ttl)

    def heartbeat_timeout(self):
        """
        Get socket option `heartbeat_timeout`.
        """
        return plain.Zsock.heartbeat_timeout(self)

    def set_heartbeat_timeout(self, heartbeat_timeout):
        """
        Set socket option `heartbeat_timeout`.
        """
        return plain.Zsock.set_heartbeat_timeout(self, heartbeat_timeout)

    def tos(self):
        """
        Get socket option `tos`.
        """
        return plain.Zsock.tos(self)

    def set_tos(self, tos):
        """
        Set socket option `tos`.
        """
        return plain.Zsock.set_tos(self, tos)

    def set_router_handover(self, router_handover):
        """
        Set socket option `router_handover`.
        """
        return plain.Zsock.set_router_handover(self, router_handover)

    def set_router_mandatory(self, router_mandatory):
        """
        Set socket option `router_mandatory`.
        """
        return plain.Zsock.set_router_mandatory(self, router_mandatory)

    def set_probe_router(self, probe_router):
        """
        Set socket option `probe_router`.
        """
        return plain.Zsock.set_probe_router(self, probe_router)

    def set_req_relaxed(self, req_relaxed):
        """
        Set socket option `req_relaxed`.
        """
        return plain.Zsock.set_req_relaxed(self, req_relaxed)

    def set_req_correlate(self, req_correlate):
        """
        Set socket option `req_correlate`.
        """
        return plain.Zsock.set_req_correlate(self, req_correlate)

    def set_conflate(self, conflate):
        """
        Set socket option `conflate`.
        """
        return plain.Zsock.set_conflate(self, conflate)

    def zap_domain(self):
        """
        Get socket option `zap_domain`.
        """
        return plain.Zsock.zap_domain(self)

    def set_zap_domain(self, zap_domain):
        """
        Set socket option `zap_domain`.
        """
        return plain.Zsock.set_zap_domain(self, zap_domain)

    def mechanism(self):
        """
        Get socket option `mechanism`.
        """
        return plain.Zsock.mechanism(self)

    def plain_server(self):
        """
        Get socket option `plain_server`.
        """
        return plain.Zsock.plain_server(self)

    def set_plain_server(self, plain_server):
        """
        Set socket option `plain_server`.
        """
        return plain.Zsock.set_plain_server(self, plain_server)

    def plain_username(self):
        """
        Get socket option `plain_username`.
        """
        return plain.Zsock.plain_username(self)

    def set_plain_username(self, plain_username):
        """
        Set socket option `plain_username`.
        """
        return plain.Zsock.set_plain_username(self, plain_username)

    def plain_password(self):
        """
        Get socket option `plain_password`.
        """
        return plain.Zsock.plain_password(self)

    def set_plain_password(self, plain_password):
        """
        Set socket option `plain_password`.
        """
        return plain.Zsock.set_plain_password(self, plain_password)

    def curve_server(self):
        """
        Get socket option `curve_server`.
        """
        return plain.Zsock.curve_server(self)

    def set_curve_server(self, curve_server):
        """
        Set socket option `curve_server`.
        """
        return plain.Zsock.set_curve_server(self, curve_server)

    def curve_publickey(self):
        """
        Get socket option `curve_publickey`.
        """
        return plain.Zsock.curve_publickey(self)

    def set_curve_publickey(self, curve_publickey):
        """
        Set socket option `curve_publickey`.
        """
        return plain.Zsock.set_curve_publickey(self, curve_publickey)

    def set_curve_publickey_bin(self, curve_publickey):
        """
        Set socket option `curve_publickey` from 32-octet binary
        """
        return plain.Zsock.set_curve_publickey_bin(self, curve_publickey)

    def curve_secretkey(self):
        """
        Get socket option `curve_secretkey`.
        """
        return plain.Zsock.curve_secretkey(self)

    def set_curve_secretkey(self, curve_secretkey):
        """
        Set socket option `curve_secretkey`.
        """
        return plain.Zsock.set_curve_secretkey(self, curve_secretkey)

    def set_curve_secretkey_bin(self, curve_secretkey):
        """
        Set socket option `curve_secretkey` from 32-octet binary
        """
        return plain.Zsock.set_curve_secretkey_bin(self, curve_secretkey)

    def curve_serverkey(self):
        """
        Get socket option `curve_serverkey`.
        """
        return plain.Zsock.curve_serverkey(self)

    def set_curve_serverkey(self, curve_serverkey):
        """
        Set socket option `curve_serverkey`.
        """
        return plain.Zsock.set_curve_serverkey(self, curve_serverkey)

    def set_curve_serverkey_bin(self, curve_serverkey):
        """
        Set socket option `curve_serverkey` from 32-octet binary
        """
        return plain.Zsock.set_curve_serverkey_bin(self, curve_serverkey)

    def gssapi_server(self):
        """
        Get socket option `gssapi_server`.
        """
        return plain.Zsock.gssapi_server(self)

    def set_gssapi_server(self, gssapi_server):
        """
        Set socket option `gssapi_server`.
        """
        return plain.Zsock.set_gssapi_server(self, gssapi_server)

    def gssapi_plaintext(self):
        """
        Get socket option `gssapi_plaintext`.
        """
        return plain.Zsock.gssapi_plaintext(self)

    def set_gssapi_plaintext(self, gssapi_plaintext):
        """
        Set socket option `gssapi_plaintext`.
        """
        return plain.Zsock.set_gssapi_plaintext(self, gssapi_plaintext)

    def gssapi_principal(self):
        """
        Get socket option `gssapi_principal`.
        """
        return plain.Zsock.gssapi_principal(self)

    def set_gssapi_principal(self, gssapi_principal):
        """
        Set socket option `gssapi_principal`.
        """
        return plain.Zsock.set_gssapi_principal(self, gssapi_principal)

    def gssapi_service_principal(self):
        """
        Get socket option `gssapi_service_principal`.
        """
        return plain.Zsock.gssapi_service_principal(self)

    def set_gssapi_service_principal(self, gssapi_service_principal):
        """
        Set socket option `gssapi_service_principal`.
        """
        return plain.Zsock.set_gssapi_service_principal(self, gssapi_service_principal)

    def ipv6(self):
        """
        Get socket option `ipv6`.
        """
        return plain.Zsock.ipv6(self)

    def set_ipv6(self, ipv6):
        """
        Set socket option `ipv6`.
        """
        return plain.Zsock.set_ipv6(self, ipv6)

    def immediate(self):
        """
        Get socket option `immediate`.
        """
        return plain.Zsock.immediate(self)

    def set_immediate(self, immediate):
        """
        Set socket option `immediate`.
        """
        return plain.Zsock.set_immediate(self, immediate)

    def set_router_raw(self, router_raw):
        """
        Set socket option `router_raw`.
        """
        return plain.Zsock.set_router_raw(self, router_raw)

    def ipv4only(self):
        """
        Get socket option `ipv4only`.
        """
        return plain.Zsock.ipv4only(self)

    def set_ipv4only(self, ipv4only):
        """
        Set socket option `ipv4only`.
        """
        return plain.Zsock.set_ipv4only(self, ipv4only)

    def set_delay_attach_on_connect(self, delay_attach_on_connect):
        """
        Set socket option `delay_attach_on_connect`.
        """
        return plain.Zsock.set_delay_attach_on_connect(self, delay_attach_on_connect)

    def type(self):
        """
        Get socket option `type`.
        """
        return plain.Zsock.type(self)

    def sndhwm(self):
        """
        Get socket option `sndhwm`.
        """
        return plain.Zsock.sndhwm(self)

    def set_sndhwm(self, sndhwm):
        """
        Set socket option `sndhwm`.
        """
        return plain.Zsock.set_sndhwm(self, sndhwm)

    def rcvhwm(self):
        """
        Get socket option `rcvhwm`.
        """
        return plain.Zsock.rcvhwm(self)

    def set_rcvhwm(self, rcvhwm):
        """
        Set socket option `rcvhwm`.
        """
        return plain.Zsock.set_rcvhwm(self, rcvhwm)

    def affinity(self):
        """
        Get socket option `affinity`.
        """
        return plain.Zsock.affinity(self)

    def set_affinity(self, affinity):
        """
        Set socket option `affinity`.
        """
        return plain.Zsock.set_affinity(self, affinity)

    def set_subscribe(self, subscribe):
        """
        Set socket option `subscribe`.
        """
        return plain.Zsock.set_subscribe(self, subscribe)

    def set_unsubscribe(self, unsubscribe):
        """
        Set socket option `unsubscribe`.
        """
        return plain.Zsock.set_unsubscribe(self, unsubscribe)

    def identity(self):
        """
        Get socket option `identity`.
        """
        return plain.Zsock.identity(self)

    def set_identity(self, identity):
        """
        Set socket option `identity`.
        """
        return plain.Zsock.set_identity(self, identity)

    def rate(self):
        """
        Get socket option `rate`.
        """
        return plain.Zsock.rate(self)

    def set_rate(self, rate):
        """
        Set socket option `rate`.
        """
        return plain.Zsock.set_rate(self, rate)

    def recovery_ivl(self):
        """
        Get socket option `recovery_ivl`.
        """
        return plain.Zsock.recovery_ivl(self)

    def set_recovery_ivl(self, recovery_ivl):
        """
        Set socket option `recovery_ivl`.
        """
        return plain.Zsock.set_recovery_ivl(self, recovery_ivl)

    def sndbuf(self):
        """
        Get socket option `sndbuf`.
        """
        return plain.Zsock.sndbuf(self)

    def set_sndbuf(self, sndbuf):
        """
        Set socket option `sndbuf`.
        """
        return plain.Zsock.set_sndbuf(self, sndbuf)

    def rcvbuf(self):
        """
        Get socket option `rcvbuf`.
        """
        return plain.Zsock.rcvbuf(self)

    def set_rcvbuf(self, rcvbuf):
        """
        Set socket option `rcvbuf`.
        """
        return plain.Zsock.set_rcvbuf(self, rcvbuf)

    def linger(self):
        """
        Get socket option `linger`.
        """
        return plain.Zsock.linger(self)

    def set_linger(self, linger):
        """
        Set socket option `linger`.
        """
        return plain.Zsock.set_linger(self, linger)

    def reconnect_ivl(self):
        """
        Get socket option `reconnect_ivl`.
        """
        return plain.Zsock.reconnect_ivl(self)

    def set_reconnect_ivl(self, reconnect_ivl):
        """
        Set socket option `reconnect_ivl`.
        """
        return plain.Zsock.set_reconnect_ivl(self, reconnect_ivl)

    def reconnect_ivl_max(self):
        """
        Get socket option `reconnect_ivl_max`.
        """
        return plain.Zsock.reconnect_ivl_max(self)

    def set_reconnect_ivl_max(self, reconnect_ivl_max):
        """
        Set socket option `reconnect_ivl_max`.
        """
        return plain.Zsock.set_reconnect_ivl_max(self, reconnect_ivl_max)

    def backlog(self):
        """
        Get socket option `backlog`.
        """
        return plain.Zsock.backlog(self)

    def set_backlog(self, backlog):
        """
        Set socket option `backlog`.
        """
        return plain.Zsock.set_backlog(self, backlog)

    def maxmsgsize(self):
        """
        Get socket option `maxmsgsize`.
        """
        return plain.Zsock.maxmsgsize(self)

    def set_maxmsgsize(self, maxmsgsize):
        """
        Set socket option `maxmsgsize`.
        """
        return plain.Zsock.set_maxmsgsize(self, maxmsgsize)

    def multicast_hops(self):
        """
        Get socket option `multicast_hops`.
        """
        return plain.Zsock.multicast_hops(self)

    def set_multicast_hops(self, multicast_hops):
        """
        Set socket option `multicast_hops`.
        """
        return plain.Zsock.set_multicast_hops(self, multicast_hops)

    def rcvtimeo(self):
        """
        Get socket option `rcvtimeo`.
        """
        return plain.Zsock.rcvtimeo(self)

    def set_rcvtimeo(self, rcvtimeo):
        """
        Set socket option `rcvtimeo`.
        """
        return plain.Zsock.set_rcvtimeo(self, rcvtimeo)

    def sndtimeo(self):
        """
        Get socket option `sndtimeo`.
        """
        return plain.Zsock.sndtimeo(self)

    def set_sndtimeo(self, sndtimeo):
        """
        Set socket option `sndtimeo`.
        """
        return plain.Zsock.set_sndtimeo(self, sndtimeo)

    def set_xpub_verbose(self, xpub_verbose):
        """
        Set socket option `xpub_verbose`.
        """
        return plain.Zsock.set_xpub_verbose(self, xpub_verbose)

    def tcp_keepalive(self):
        """
        Get socket option `tcp_keepalive`.
        """
        return plain.Zsock.tcp_keepalive(self)

    def set_tcp_keepalive(self, tcp_keepalive):
        """
        Set socket option `tcp_keepalive`.
        """
        return plain.Zsock.set_tcp_keepalive(self, tcp_keepalive)

    def tcp_keepalive_idle(self):
        """
        Get socket option `tcp_keepalive_idle`.
        """
        return plain.Zsock.tcp_keepalive_idle(self)

    def set_tcp_keepalive_idle(self, tcp_keepalive_idle):
        """
        Set socket option `tcp_keepalive_idle`.
        """
        return plain.Zsock.set_tcp_keepalive_idle(self, tcp_keepalive_idle)

    def tcp_keepalive_cnt(self):
        """
        Get socket option `tcp_keepalive_cnt`.
        """
        return plain.Zsock.tcp_keepalive_cnt(self)

    def set_tcp_keepalive_cnt(self, tcp_keepalive_cnt):
        """
        Set socket option `tcp_keepalive_cnt`.
        """
        return plain.Zsock.set_tcp_keepalive_cnt(self, tcp_keepalive_cnt)

    def tcp_keepalive_intvl(self):
        """
        Get socket option `tcp_keepalive_intvl`.
        """
        return plain.Zsock.tcp_keepalive_intvl(self)

    def set_tcp_keepalive_intvl(self, tcp_keepalive_intvl):
        """
        Set socket option `tcp_keepalive_intvl`.
        """
        return plain.Zsock.set_tcp_keepalive_intvl(self, tcp_keepalive_intvl)

    def tcp_accept_filter(self):
        """
        Get socket option `tcp_accept_filter`.
        """
        return plain.Zsock.tcp_accept_filter(self)

    def set_tcp_accept_filter(self, tcp_accept_filter):
        """
        Set socket option `tcp_accept_filter`.
        """
        return plain.Zsock.set_tcp_accept_filter(self, tcp_accept_filter)

    def rcvmore(self):
        """
        Get socket option `rcvmore`.
        """
        return plain.Zsock.rcvmore(self)

    def fd(self):
        """
        Get socket option `fd`.
        """
        return plain.Zsock.fd(self)

    def events(self):
        """
        Get socket option `events`.
        """
        return plain.Zsock.events(self)

    def last_endpoint(self):
        """
        Get socket option `last_endpoint`.
        """
        return plain.Zsock.last_endpoint(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zsock.test(verbose)



class Zstr(plain.Zstr):
    @staticmethod
    def recv(source):
        """
        Receive C string from socket. Caller must free returned string using
zstr_free(). Returns NULL if the context is being terminated or the
process was interrupted.
        """
        return plain.Zstr.recv(source)

    @staticmethod
    def recvx(source, string_p, *args):
        """
        Receive a series of strings (until NULL) from multipart data.
Each string is allocated and filled with string data; if there
are not enough frames, unallocated strings are set to NULL.
Returns -1 if the message could not be read, else returns the
number of strings filled, zero or more. Free each returned string
using zstr_free(). If not enough strings are provided, remaining
multipart frames in the message are dropped.
        """
        return plain.Zstr.recvx(source, string_p, *args)

    @staticmethod
    def send(dest, string):
        """
        Send a C string to a socket, as a frame. The string is sent without
trailing null byte; to read this you can use zstr_recv, or a similar
method that adds a null terminator on the received string. String
may be NULL, which is sent as "".
        """
        return plain.Zstr.send(dest, string)

    @staticmethod
    def sendm(dest, string):
        """
        Send a C string to a socket, as zstr_send(), with a MORE flag, so that
you can send further strings in the same multi-part message.
        """
        return plain.Zstr.sendm(dest, string)

    @staticmethod
    def sendf(dest, format, *args):
        """
        Send a formatted string to a socket. Note that you should NOT use
user-supplied strings in the format (they may contain '%' which
will create security holes).
        """
        return plain.Zstr.sendf(dest, format, *args)

    @staticmethod
    def sendfm(dest, format, *args):
        """
        Send a formatted string to a socket, as for zstr_sendf(), with a
MORE flag, so that you can send further strings in the same multi-part
message.
        """
        return plain.Zstr.sendfm(dest, format, *args)

    @staticmethod
    def sendx(dest, string, *args):
        """
        Send a series of strings (until NULL) as multipart data
Returns 0 if the strings could be sent OK, or -1 on error.
        """
        return plain.Zstr.sendx(dest, string, *args)

    @staticmethod
    def str(source):
        """
        Accepts a void pointer and returns a fresh character string. If source
is null, returns an empty string.
        """
        return plain.Zstr.str(source)

    @staticmethod
    def free(string_p):
        """
        Free a provided string, and nullify the parent pointer. Safe to call on
a null pointer.
        """
        return plain.Zstr.free(string_p)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zstr.test(verbose)



class Ztrie(plain.Ztrie):
    def __init__(self, *args, **kw):
        """
        Creates a new ztrie.
        """
        plain.Ztrie.__init__(*args, **kw)

    def insert_route(self, path, data, destroy_data_fn):
        """
        Inserts a new route into the tree and attaches the data. Returns -1
if the route already exists, otherwise 0. This method takes ownership of
the provided data if a destroy_data_fn is provided.
        """
        return plain.Ztrie.insert_route(self, path, data, destroy_data_fn)

    def remove_route(self, path):
        """
        Removes a route from the trie and destroys its data. Returns -1 if the
route does not exists, otherwise 0.
the start of the list call zlist_first (). Advances the cursor.
        """
        return plain.Ztrie.remove_route(self, path)

    def matches(self, path):
        """
        Returns true if the path matches a route in the tree, otherwise false.
        """
        return plain.Ztrie.matches(self, path)

    def hit_data(self):
        """
        Returns the data of a matched route from last ztrie_matches. If the path
did not match, returns NULL. Do not delete the data as it's owned by
ztrie.
        """
        return plain.Ztrie.hit_data(self)

    def hit_parameter_count(self):
        """
        Returns the count of parameters that a matched route has.
        """
        return plain.Ztrie.hit_parameter_count(self)

    def hit_parameters(self):
        """
        Returns the parameters of a matched route with named regexes from last
ztrie_matches. If the path did not match or the route did not contain any
named regexes, returns NULL.
        """
        return plain.Ztrie.hit_parameters(self)

    def hit_asterisk_match(self):
        """
        Returns the asterisk matched part of a route, if there has been no match
or no asterisk match, returns NULL.
        """
        return plain.Ztrie.hit_asterisk_match(self)

    def print_(self):
        """
        Print the trie
        """
        return plain.Ztrie.print_(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Ztrie.test(verbose)



class Zuuid(plain.Zuuid):
    def __init__(self, *args, **kw):
        """
        Create a new UUID object.
        """
        plain.Zuuid.__init__(*args, **kw)

    @staticmethod
    def new_from(source):
        """
        Create UUID object from supplied ZUUID_LEN-octet value.
        """
        return plain.Zuuid.new_from(source)

    def set(self, source):
        """
        Set UUID to new supplied ZUUID_LEN-octet value.
        """
        return plain.Zuuid.set(self, source)

    def set_str(self, source):
        """
        Set UUID to new supplied string value skipping '-' and '{' '}'
optional delimiters. Return 0 if OK, else returns -1.
        """
        return plain.Zuuid.set_str(self, source)

    def data(self):
        """
        Return UUID binary data.
        """
        return plain.Zuuid.data(self)

    def size(self):
        """
        Return UUID binary size
        """
        return plain.Zuuid.size(self)

    def str(self):
        """
        Returns UUID as string
        """
        return plain.Zuuid.str(self)

    def str_canonical(self):
        """
        Return UUID in the canonical string format: 8-4-4-4-12, in lower
case. Caller does not modify or free returned value. See
http://en.wikipedia.org/wiki/Universally_unique_identifier
        """
        return plain.Zuuid.str_canonical(self)

    def export(self, target):
        """
        Store UUID blob in target array
        """
        return plain.Zuuid.export(self, target)

    def eq(self, compare):
        """
        Check if UUID is same as supplied value
        """
        return plain.Zuuid.eq(self, compare)

    def neq(self, compare):
        """
        Check if UUID is different from supplied value
        """
        return plain.Zuuid.neq(self, compare)

    def dup(self):
        """
        Make copy of UUID object; if uuid is null, or memory was exhausted,
returns null.
        """
        return plain.Zuuid.dup(self)

    @staticmethod
    def test(verbose):
        """
        Self test of this class.
        """
        return plain.Zuuid.test(verbose)




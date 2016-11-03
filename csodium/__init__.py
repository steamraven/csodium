"""
A standalone Python interface for libsodium.
"""

from six import binary_type

from ._impl import (
    ffi,
    lib,
)

if lib.sodium_init() < 0:  # pragma: no cover
    raise RuntimeError("libsodium initialization failed")


SODIUM_VERSION_STRING = ffi.string(lib.sodium_version_string()).decode('utf-8')
SODIUM_VERSION = tuple(map(int, SODIUM_VERSION_STRING.split('.')))


def _raise_on_error(return_code):
    if return_code != 0:
        raise ValueError("Call returned %s" % return_code)


def _assert_len(name, buf, size, max_size=None):
    assert buf, "%s cannot be NULL" % name

    if max_size:
        assert size <= len(buf) <= max_size, (
            "%s must be between %d and %d bytes long" % (name, size, max_size)
        )
    else:
        assert len(buf) == size, "%s must be %d byte(s) long" % (name, size)


def _assert_min_len(name, buf, min_size):
    assert buf, "%s cannot be NULL" % name

    assert min_size <= len(buf), (
        "%s must be at least %d bytes long" % (name, min_size)
    )


def _from_buffer(buf):
    return ffi.cast("unsigned char *", ffi.from_buffer(buf))

# random family.


def randombytes(size):
    """Returns a number of random bytes

    See Also:
        libsodium documentation:
        `Generating Random Data
        <https://download.libsodium.org/doc/generating_random_data/>`__

    Args:
        size (:obj:`int`): Number of bytes to return

    Returns:
        :obj:`bytes`: Random bytes of length size
    """
    buf = bytearray(size)
    lib.randombytes(_from_buffer(buf), size)
    return binary_type(buf)

# crypto_box family.
crypto_box_BEFORENMBYTES = lib.crypto_box_beforenmbytes()
"""Length of context for :py:func:`crypto_box_beforenm` in bytes`"""
crypto_box_MACBYTES = lib.crypto_box_macbytes()
"""Length of extra bytes needed for MAC for crypto_box_*"""
crypto_box_NONCEBYTES = lib.crypto_box_noncebytes()
"""Length of nonce for crypto_box_* in bytes"""
crypto_box_PUBLICKEYBYTES = lib.crypto_box_publickeybytes()
"""Length of Public Key for crypto_box_* in bytes"""
crypto_box_SEALBYTES = lib.crypto_box_sealbytes()
"""Length of extra bytes needed for crypto_box_seal_*"""
crypto_box_SECRETKEYBYTES = lib.crypto_box_secretkeybytes()
"""Length of Secret Key for crypto_box_* in bytes"""
crypto_box_SEEDBYTES = lib.crypto_box_seedbytes()
"""Length of seed for :py:func:`crypto_box_seed_keypair` in bytes"""


def crypto_box_keypair():
    """Randomly generate a public key/secret key pair

    libsodium documentation:
    `Public-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    public-key_cryptography/authenticated_encryption.html
    #key-pair-generation>`__

    Returns:
        (:obj:`bytes`, :obj:`bytes`): 2-element tuple containing:

        - **pk** (:obj:`bytes`): Public Key of length
          :py:const:`crypto_box_PUBLICKEYBYTES`
        - **sk** (:obj:`bytes`): Secret Key of length
          :py:const:`crypto_box_SECRETKEYBYTES`
    """
    pk = bytearray(crypto_box_PUBLICKEYBYTES)
    sk = bytearray(crypto_box_SECRETKEYBYTES)
    _raise_on_error(
        lib.crypto_box_keypair(
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(pk), binary_type(sk)


def crypto_box_seed_keypair(seed):
    """Generate a public/secret key pair from a seed

    libsodium documentation:
    `Public-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    public-key_cryptography/authenticated_encryption.html
    #key-pair-generation>`__

    Args:
        seed (:any:`bytes-like<bytes-like object>`): Seed of length
            :py:const:`crypto_box_SEEDBYTES`

    Returns:
        (:obj:`bytes`, :obj:`bytes`): 2-element tuple containing:

        - **pk** (:obj:`bytes`): Public Key of length
          :py:const:`crypto_box_PUBLICKEYBYTES`
        - **sk** (:obj:`bytes`): Secret Key of length
          :py:const:`crypto_box_SECRETKEYBYTES`
    """
    _assert_len('seed', seed, crypto_box_SEEDBYTES)

    pk = bytearray(crypto_box_PUBLICKEYBYTES)
    sk = bytearray(crypto_box_SECRETKEYBYTES)
    _raise_on_error(
        lib.crypto_box_seed_keypair(
            _from_buffer(pk),
            _from_buffer(sk),
            _from_buffer(seed),
        ),
    )

    return binary_type(pk), binary_type(sk)


def crypto_box_beforenm(pk, sk):
    """Precomputes shared key to send/receive multiple messages

    libsodium documentation:
    `Public-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    public-key_cryptography/authenticated_encryption.html
    #precalculation-interface>`__

    Args:
        pk (:any:`bytes-like<bytes-like object>`): Their Public Key of length
            :py:const:`crypto_box_PUBLICKEYBYTES`
        sk (:any:`bytes-like<bytes-like object>`): Our Secret Key of length
            :py:const:`crypto_box_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: Context for crypto_box_*_afternm of length
        :py:const:`crypto_box_BEFORENMBYTES`
    """

    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    k = bytearray(crypto_box_BEFORENMBYTES)
    _raise_on_error(
        lib.crypto_box_beforenm(
            _from_buffer(k),
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(k)


def crypto_box(msg, nonce, pk, sk):
    """Encrypt a message using Public Key Authenticated Encryption

    libsodium documentation (see crypto_box_easy):
    `Public-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    public-key_cryptography/authenticated_encryption.html
    #combined-mode>`__

    Args:
        msg (:any:`bytes-like<bytes-like object>`): Message to encrypt
        nonce (:any:`bytes-like<bytes-like object>`): A unique nonce of length
            :py:const:`crypto_box_NONCEBYTES`
        pk (:any:`bytes-like<bytes-like object>`): Their Public Key of length
            :py:const:`crypto_box_PUBLICKEYBYTES`
        sk (:any:`bytes-like<bytes-like object>`): Our Secret Key of length
            :py:const:`crypto_box_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: an encrypted message of length *len(msg)* +
        :py:const:`crypto_box_MACBYTES`

    Notes:
        Nonce doesn't have to confidential, but must be unique for a pair of
        public and secret keys.  One ease way to generate a nonce is with
        :py:func:`randombytes`. It is also acceptable to use a simple
        incrementing counter as long as it is *never* re-used.

        The messages are encrypted using a shared key: a sender can decrypt
        its own messages, which is generally not an issue for online
        protocols. If this is not acceptable, use
        :py:func:`crypto_box_seal` followed by :py:func:`crypto_sign`.

        This function is not meant to provide non-repudiation. If this is not
        acceptable, use :py:func:`crypto_box_seal` followed by
        :py:func:`crypto_sign`.
    """

    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    c = bytearray(crypto_box_MACBYTES + len(msg))
    _raise_on_error(
        lib.crypto_box_easy(
            _from_buffer(c),
            _from_buffer(msg),
            len(msg),
            _from_buffer(nonce),
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(c)


def crypto_box_afternm(msg, nonce, k):
    """Encrypt a message using context from :py:func:`crypto_box_beforenm`

    libsodium documentation (see crypto_box_easy_afternm):
    `Public-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    public-key_cryptography/authenticated_encryption.html
    #precalculation-interface>`__

    Args:
        msg (:any:`bytes-like<bytes-like object>`): Message to encrypt
        nonce (:any:`bytes-like<bytes-like object>`): A unique nonce of length
            :py:const:`crypto_box_NONCEBYTES`
        k (:any:`bytes-like<bytes-like object>`): Context generated with
            :py:func:`crypto_box_beforenm` of length
            :py:const:`crypto_box_BEFORENMBYTES`

    Returns:
        :obj:`bytes`: an encrypted message of length *len(msg)* +
        :py:const:`crypto_box_MACBYTES`

    Notes:
        Nonce doesn't have to confidential, but must be unique for a pair of
        public and secret keys.  One ease way to generate a nonce is with
        :py:func:`randombytes`. It is also acceptable to use a simple
        incrementing counter as long as it is *never* re-used.

        The messages are encrypted using a shared key: a sender can decrypt
        its own messages, which is generally not an issue for online
        protocols. If this is not acceptable, use
        :py:func:`crypto_box_seal` followed by :py:func:`crypto_sign`.

        This function is not meant to provide non-repudiation. If this is not
        acceptable, use :py:func:`crypto_box_seal` followed by
        :py:func:`crypto_sign`.
    """
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('k', k, crypto_box_BEFORENMBYTES)

    c = bytearray(crypto_box_MACBYTES + len(msg))
    _raise_on_error(
        lib.crypto_box_easy_afternm(
            _from_buffer(c),
            _from_buffer(msg),
            len(msg),
            _from_buffer(nonce),
            _from_buffer(k),
        ),
    )

    return binary_type(c)


def crypto_box_open(c, nonce, pk, sk):
    """Authenticate and decrypt a message using Public Key Authenticated
    Encryption

    libsodium documentation (see crypto_box_easy_open):
    `Public-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    public-key_cryptography/authenticated_encryption.html
    #combined-mode>`__

    Args:
        c (:any:`bytes-like<bytes-like object>`): Cipher text of at least
            length :py:const:`crypto_box_MACBYTES`
        nonce (:any:`bytes-like<bytes-like object>`): A unique nonce of length
            :py:const:`crypto_box_NONCEBYTES`
        pk (:any:`bytes-like<bytes-like object>`): Their Public Key of length
            :py:const:`crypto_box_PUBLICKEYBYTES`
        sk (:any:`bytes-like<bytes-like object>`): Our Secret Key of length
            :py:const:`crypto_box_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: the decrypted message of length *len(c)* -
        :py:const:`crypto_box_MACBYTES`

    Raises:
        ValueError: The message cannot be authenticated or decrypted
    """
    _assert_min_len('c', c, crypto_box_MACBYTES)
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    msg = bytearray(len(c) - crypto_box_MACBYTES)
    _raise_on_error(
        lib.crypto_box_open_easy(
            _from_buffer(msg),
            _from_buffer(c),
            len(c),
            _from_buffer(nonce),
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(msg)


def crypto_box_open_afternm(c, nonce, k):
    """Authenticate and decrypt a message using context from
    :py:func:`crypto_box_beforenm`

    libsodium documentation (see crypto_box_easy_open_afternm):
    `Public-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    public-key_cryptography/authenticated_encryption.html
    #precalculation-interface>`__

    Args:
        c (:any:`bytes-like<bytes-like object>`): Cipher text of at least
            length :py:const:`crypto_box_MACBYTES`
        nonce (:any:`bytes-like<bytes-like object>`): A unique nonce of length
            :py:const:`crypto_box_NONCEBYTES`
        k (:any:`bytes-like<bytes-like object>`): Context generated with
            :py:func:`crypto_box_beforenm` of length
            :py:const:`crypto_box_BEFORENMBYTES`

    Returns:
        :obj:`bytes`: the decrypted message of length *len(c)* -
        :py:const:`crypto_box_MACBYTES`

    Raises:
        ValueError: The message cannot be authenticated or decrypted
    """
    _assert_min_len('c', c, crypto_box_MACBYTES)
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('k', k, crypto_box_BEFORENMBYTES)

    msg = bytearray(len(c) - crypto_box_MACBYTES)
    _raise_on_error(
        lib.crypto_box_open_easy_afternm(
            _from_buffer(msg),
            _from_buffer(c),
            len(c),
            _from_buffer(nonce),
            _from_buffer(k),
        ),
    )

    return binary_type(msg)


def crypto_box_seal(msg, pk):
    """Encrypts a message using a Public Key

    libsodium documentation:
    `Public-Key Sealed Boxes
    <https://download.libsodium.org/doc/
    public-key_cryptography/sealed_boxes.html
    #usage>`__

    Args:
        msg (:any:`bytes-like<bytes-like object>`): Message to be encrypted
        pk (:any:`bytes-like<bytes-like object>`): Public key of length
            :py:const:`crypto_box_PUBLICKEYBYTES`

    Returns:
        :obj:`bytes`: the encrypted message of length len(msg) +
        :py:const:`crypto_box_SEALBYTES`

    Note:
        This function does not provide any authentication of the message.
        Please see :py:func:`crypto_box` or :py:func:`crypto_sign`
    """

    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)

    c = bytearray(len(msg) + crypto_box_SEALBYTES)
    _raise_on_error(
        lib.crypto_box_seal(
            _from_buffer(c),
            _from_buffer(msg),
            len(msg),
            _from_buffer(pk),
        ),
    )

    return binary_type(c)


def crypto_box_seal_open(c, pk, sk):
    """Decrypts a msg using a public/secret key-pair

    libsodium documentation:
    `Public-Key Sealed Boxes
    <https://download.libsodium.org/doc/
    public-key_cryptography/sealed_boxes.html
    #usage>`__

    Args:
        c (:any:`bytes-like<bytes-like object>`): Message to be decrypted of
            at least length :py:const:`crypto_box_SEALBYTES`
        pk (:any:`bytes-like<bytes-like object>`): Our public key of length
            :py:const:`crypto_box_PUBLICKEYBYTES`
        sk (:any:`bytes-like<bytes-like object>`): Our secret key of length
            :py:const:`crypto_box_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: the decrypted message of length *len(c)* -
        :py:const:`crypto_box_SEALBYTES`

    Raises:
        ValueError: The message cannot be decrypted
    """

    _assert_min_len('c', c, crypto_box_SEALBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    msg = bytearray(len(c) - crypto_box_SEALBYTES)
    _raise_on_error(
        lib.crypto_box_seal_open(
            _from_buffer(msg),
            _from_buffer(c),
            len(c),
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(msg)


def crypto_box_detached(msg, nonce, pk, sk):
    """Encrypt a message using Public Key Authenticated Encryption

    libsodium documentation:
    `Public-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    public-key_cryptography/authenticated_encryption.html
    #detached-mode>`__

    Args:
        msg (:any:`bytes-like<bytes-like object>`): Message to encrypt
        nonce (:any:`bytes-like<bytes-like object>`): A unique nonce of length
            :py:const:`crypto_box_NONCEBYTES`
        pk (:any:`bytes-like<bytes-like object>`): Their Public Key of length
            :py:const:`crypto_box_PUBLICKEYBYTES`
        sk (:any:`bytes-like<bytes-like object>`): Our Secret Key of length
            :py:const:`crypto_box_SECRETBYTES`

    Returns:
        (:obj:`bytes`, :obj:`bytes`): 2-element tuple containing

        - **c** (:obj:`bytes`): The encrypted message with same length as msg
        - **mac** (:obj:`bytes`): The MAC of length
          :py:const:`crypto_box_MACBYTES`

    Notes:
        Nonce doesn't have to confidential, but must be unique for a pair of
        public and secret keys.  One ease way to generate a nonce is with
        :py:func:`randombytes`. It is also acceptable to use a simple
        incrementing counter as long as it is *never* re-used.

        The messages are encrypted using a shared key: a sender can decrypt
        its own messages, which is generally not an issue for online
        protocols. If this is not acceptable, use
        :py:func:`crypto_box_seal` followed by :py:func:`crypto_sign`.

        This function is not meant to provide non-repudiation. If this is not
        acceptable, use :py:func:`crypto_box_seal` followed by
        :py:func:`crypto_sign`.
    """
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    c = bytearray(len(msg))
    mac = bytearray(crypto_box_MACBYTES)
    _raise_on_error(
        lib.crypto_box_detached(
            _from_buffer(c),
            _from_buffer(mac),
            _from_buffer(msg),
            len(msg),
            _from_buffer(nonce),
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(c), binary_type(mac)


def crypto_box_open_detached(c, mac, nonce, pk, sk):
    """Authenticate and decrypt a message and mac using Public Key
    Authenticated Encryption

    libsodium documentation:
    `Public-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    public-key_cryptography/authenticated_encryption.html
    #detached-mode>`__

    Args:
        c (:any:`bytes-like<bytes-like object>`): msg to encrypt
        mac (:any:`bytes-like<bytes-like object>`): Authentication tag (MAC)
            of length :py:const:`crypto_box_MACBYTES`
        nonce (:any:`bytes-like<bytes-like object>`): A unique nonce of length
            :py:const:`crypto_box_NONCEBYTES`
        pk (:any:`bytes-like<bytes-like object>`): Their Public Key of length
            :py:const:`crypto_box_PUBLICKEYBYTES`
        sk (:any:`bytes-like<bytes-like object>`): Our Secret Key of length
            :py:const:`crypto_box_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: The decrypted message with length equal to the cipher
        text
    """
    _assert_len('mac', mac, crypto_box_MACBYTES)
    _assert_len('nonce', nonce, crypto_box_NONCEBYTES)
    _assert_len('pk', pk, crypto_box_PUBLICKEYBYTES)
    _assert_len('sk', sk, crypto_box_SECRETKEYBYTES)

    msg = bytearray(len(c))
    _raise_on_error(
        lib.crypto_box_open_detached(
            _from_buffer(msg),
            _from_buffer(c),
            _from_buffer(mac),
            len(c),
            _from_buffer(nonce),
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(msg)


# crypto_secretbox family.
crypto_secretbox_KEYBYTES = lib.crypto_secretbox_keybytes()
"""Length of Secret Key for crypto_secretbox_* in bytes"""
crypto_secretbox_NONCEBYTES = lib.crypto_secretbox_noncebytes()
"""Length of Nonce for crypto_secretbox_* in bytes"""
crypto_secretbox_MACBYTES = lib.crypto_secretbox_macbytes()
"""Length of extra bytes needed for MAC for crypto_secretbox_*"""


def crypto_secretbox(msg, nonce, k):
    """Encrypts a message using a shared secret-key

    libsodium documentation (see crypt_secretbox_easy):
    `Secret-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    secret-key_cryptography/authenticated_encryption.html
    #combined-mode>`__

    Args:
        msg (:any:`bytes-like<bytes-like object>`): Message to encrypt
        nonce (:any:`bytes-like<bytes-like object>`): A unique nonce of length
            :py:const:`crypto_secretbox_NONCEBYTES`
        k (:any:`bytes-like<bytes-like object>`): Secret key of length
            :py:const:`crypto_secretbox_KEYBYTES`

    Returns:
        :obj:`bytes`: Encrypted msg of length *len(msg)* +
        :py:const:`crypto_secretbox_MACBYTES`

    Notes:
        Secret key can be generated from :py:func:`randombytes` or from a key
        exchange or agreement protocol.

        Nonce doesn't have to confidential, but must be unique for a secret
        key.  One ease way to generate a nonce is with :py:func:`randombytes`.
        It is also acceptable to use a simple incrementing counter as long as
        it is *never* re-used.

    """
    _assert_len('nonce', nonce, crypto_secretbox_NONCEBYTES)
    _assert_len('k', k, crypto_secretbox_KEYBYTES)

    c = bytearray(crypto_secretbox_MACBYTES + len(msg))
    _raise_on_error(
        lib.crypto_secretbox_easy(
            _from_buffer(c),
            _from_buffer(msg),
            len(msg),
            _from_buffer(nonce),
            _from_buffer(k),
        ),
    )

    return binary_type(c)


def crypto_secretbox_open(c, nonce, k):
    """Authenticates and decrypts a message using a shared secret-key

    libsodium documentation (see crypt_secretbox_easy):
    `Secret-Key Authenticated Encryption
    <https://download.libsodium.org/doc/
    secret-key_cryptography/authenticated_encryption.html
    #combined-mode>`__

    Args:
        c (:any:`bytes-like<bytes-like object>`): Message to decrypt of length
            at least :py:const:`crypto_secretbox_MACBYTES`
        nonce (:any:`bytes-like<bytes-like object>`): A unique nonce of length
            :py:const:`crypto_secretbox_NONCEBYTES`
        k (:any:`bytes-like<bytes-like object>`): Secret key of length
            :py:const:`crypto_secretbox_KEYBYTES`

    Returns:
        :obj:`bytes`: Decrypted msg of length *len(c)* -
        :py:const:`crypto_secretbox_MACBYTES`
    """
    _assert_min_len('c', c, crypto_secretbox_MACBYTES)
    _assert_len('nonce', nonce, crypto_secretbox_NONCEBYTES)
    _assert_len('k', k, crypto_secretbox_KEYBYTES)

    msg = bytearray(len(c) - crypto_secretbox_MACBYTES)
    _raise_on_error(
        lib.crypto_secretbox_open_easy(
            _from_buffer(msg),
            _from_buffer(c),
            len(c),
            _from_buffer(nonce),
            _from_buffer(k),
        ),
    )

    return binary_type(msg)


crypto_generichash_BYTES_MIN = lib.crypto_generichash_bytes_min()
"""Minimum length of return hash from crypto_generichash_*"""
crypto_generichash_BYTES_MAX = lib.crypto_generichash_bytes_max()
"""Maximum length of return hash from crypto_generichash_*"""
crypto_generichash_BYTES = lib.crypto_generichash_bytes()
"""Recommended length of return hash from crypto_generichash_*"""
crypto_generichash_KEYBYTES_MIN = lib.crypto_generichash_keybytes_min()
"""Minimum length of key for crypto_generichash_*"""
crypto_generichash_KEYBYTES_MAX = lib.crypto_generichash_keybytes_max()
"""Maximum length of key for crypto_generichash_*"""
crypto_generichash_KEYBYTES = lib.crypto_generichash_keybytes()
"""Recommended length of key for crypto_generichash_*"""
crypto_generichash_PRIMITIVE = lib.crypto_generichash_primitive()
crypto_generichash_STATEBYTES = lib.crypto_generichash_statebytes()
"""Length of state buffer for crypto_generichash_{init/update/final}*"""


def crypto_generichash(in_, key, outlen=crypto_generichash_BYTES):
    """Calculate a generic hash of input

    libsodium documentation:
    `Generic Hashing
    <https://download.libsodium.org/doc/
    hashing/generic_hashing.html
    #usage>`__

    Args:
        in\_ (:any:`bytes-like<bytes-like object>`): Input to hash
        key (:any:`bytes-like<bytes-like object>`): :py:data:`None` or a key
            of length between :py:const:`crypto_generichash_KEYBYTES_MIN` and
            :py:const:`crypto_generichash_KEYBYTES_MAX`
        outlen (:obj:`int`, optional): Length of output hash between
            :py:const:`crypto_generichash_BYTES_MIN` and
            :py:const:`crypto_generichash_BYTES_MAX`. Defaults to
            :py:const:`crypto_generichash_BYTES`

    Returns:
        :obj:`bytes`: Hash of input with length == outlen

    Note:
        Key can be generated from :py:func:`randombytes` or from a key
        exchange/agreement protocol
    """
    if key is not None:
        _assert_len(
            'key',
            key,
            crypto_generichash_KEYBYTES_MIN,
            crypto_generichash_KEYBYTES_MAX
        )

    assert crypto_generichash_BYTES_MIN <= outlen <= \
        crypto_generichash_BYTES_MAX, (
            "outlen must be between %d and %d" % (
                crypto_generichash_BYTES_MIN,
                crypto_generichash_BYTES_MAX,
            )
        )

    buf = bytearray(outlen)

    _raise_on_error(
        lib.crypto_generichash(
            ffi.cast('unsigned char *', ffi.from_buffer(buf)),
            outlen,
            _from_buffer(in_) if in_ is not None else ffi.NULL,
            len(in_ or ()),
            _from_buffer(key) if key is not None else ffi.NULL,
            len(key or ()),
        ),
    )
    return binary_type(buf)


def crypto_generichash_init(key, outlen=crypto_generichash_BYTES):
    """Initialize a state buffer to calculate a generic hash of multiple or
    streaming input

    libsodium documentation:
    `Generic Hashing
    <https://download.libsodium.org/doc/
    hashing/generic_hashing.html
    #usage>`__

    Args:
        key (:any:`bytes-like<bytes-like object>`): :py:data:`None` or a key
            of length between :py:const:`crypto_generichash_KEYBYTES_MAX` and
            :py:const:`crypto_generichash_KEYBYTES_MAX`
        outlen (:obj:`int`, optional): Length of output hash between
            :py:const:`crypto_generichash_BYTES_MIN` and
            :py:const:`crypto_generichash_BYTES_MAX`. Defaults to
            :py:const:`crypto_generichash_BYTES`

    Returns:
        :obj:`bytearray`: State of length
        :py:const:`crypto_generichash_STATEBYTES` to use with
        :py:func:`crypto_generichash_update` or
        :py:func:`crypto_generichash_final`.


    Note:
        Key can be generated from :py:func:`randombytes` or from a key
        exchange/agreement protocol
    """
    if key is not None:
        _assert_len(
            'key',
            key,
            crypto_generichash_KEYBYTES_MIN,
            crypto_generichash_KEYBYTES_MAX
        )

    assert crypto_generichash_BYTES_MIN <= outlen <= \
        crypto_generichash_BYTES_MAX, (
            "outlen must be between %d and %d" % (
                crypto_generichash_BYTES_MIN,
                crypto_generichash_BYTES_MAX,
            )
        )

    state = bytearray(crypto_generichash_STATEBYTES)

    _raise_on_error(
        lib.crypto_generichash_init(
            ffi.cast('crypto_generichash_state *', ffi.from_buffer(state)),
            _from_buffer(key) if key is not None else ffi.NULL,
            len(key or ()),
            outlen,
        ),
    )
    return state


def crypto_generichash_update(state, in_):
    """Update a state buffer with a generic hash of an input chunk

    libsodium documentation:
    `Generic Hashing
    <https://download.libsodium.org/doc/
    hashing/generic_hashing.html
    #usage>`__

    Args:
        state (:obj:`bytearray`): Hash state from
            :py:func:`crypto_generichash_init` of length
            :py:const:`crypto_generichash_STATEBYTES`
        in\_ (:any:`bytes-like<bytes-like object>`): Input to hash

    Returns:
        :obj:`bytearray`: A reference to *state*
    """

    _assert_len('state', state, crypto_generichash_STATEBYTES)

    _raise_on_error(
        lib.crypto_generichash_update(
            ffi.cast('crypto_generichash_state *', ffi.from_buffer(state)),
            _from_buffer(in_),
            len(in_),
        ),
    )

    return state


def crypto_generichash_final(state, outlen=crypto_generichash_BYTES):
    """Finalize a state buffer to calculate a generic hash

    libsodium documentation:
    `Generic Hashing
    <https://download.libsodium.org/doc/
    hashing/generic_hashing.html
    #usage>`__

    Args:
        state (:obj:`bytearray`): Hash state from
            :py:func:`crypto_generichash_init` of length
            :py:const:`crypto_generichash_STATEBYTES`
        outlen (:obj:`int`, optional): Length of output hash between
            :py:const:`crypto_generichash_BYTES_MIN` and
            :py:const:`crypto_generichash_BYTES_MAX`. Defaults to
            :py:const:`crypto_generichash_BYTES`

    Returns:
        :obj:`bytes`: Hash of all the inputs with length == outlen

    Note:
        outlen should match the outlen provided to
        :py:func:`crypto_generichash_init`
    """
    _assert_len('state', state, crypto_generichash_STATEBYTES)
    assert crypto_generichash_BYTES_MIN <= outlen <= \
        crypto_generichash_BYTES_MAX, (
            "outlen must be between %d and %d" % (
                crypto_generichash_BYTES_MIN,
                crypto_generichash_BYTES_MAX,
            )
        )

    buf = bytearray(outlen)

    _raise_on_error(
        lib.crypto_generichash_final(
            ffi.cast("crypto_generichash_state *", ffi.from_buffer(state)),
            _from_buffer(buf),
            outlen,
        ),
    )

    return binary_type(buf)


crypto_generichash_blake2b_BYTES_MIN = \
    lib.crypto_generichash_blake2b_bytes_min()
crypto_generichash_blake2b_BYTES_MAX = \
    lib.crypto_generichash_blake2b_bytes_max()
crypto_generichash_blake2b_BYTES = lib.crypto_generichash_blake2b_bytes()
crypto_generichash_blake2b_KEYBYTES_MIN = \
    lib.crypto_generichash_blake2b_keybytes_min()
crypto_generichash_blake2b_KEYBYTES_MAX = \
    lib.crypto_generichash_blake2b_keybytes_max()
crypto_generichash_blake2b_KEYBYTES = lib.crypto_generichash_blake2b_keybytes()
crypto_generichash_blake2b_SALTBYTES = \
    lib.crypto_generichash_blake2b_saltbytes()
crypto_generichash_blake2b_PERSONALBYTES = \
    lib.crypto_generichash_blake2b_personalbytes()


def crypto_generichash_blake2b_salt_personal(
    in_,
    key,
    salt,
    personal=None,
    outlen=crypto_generichash_blake2b_BYTES,
):
    _assert_len(
        'key',
        key,
        crypto_generichash_blake2b_KEYBYTES_MIN,
        crypto_generichash_blake2b_KEYBYTES_MAX,
    )
    _assert_len('salt', salt, crypto_generichash_blake2b_SALTBYTES)

    if personal is not None:
        _assert_len(
            'personal',
            personal,
            crypto_generichash_blake2b_PERSONALBYTES,
        )

    assert crypto_generichash_blake2b_BYTES_MIN <= outlen <= \
        crypto_generichash_blake2b_BYTES_MAX, (
            "outlen must be between %d and %d" % (
                crypto_generichash_blake2b_BYTES_MIN,
                crypto_generichash_blake2b_BYTES_MAX,
            )
        )

    buf = bytearray(outlen)

    _raise_on_error(
        lib.crypto_generichash_blake2b_salt_personal(
            _from_buffer(buf),
            outlen,
            _from_buffer(in_) if in_ is not None else ffi.NULL,
            len(in_ or ()),
            _from_buffer(key),
            len(key),
            _from_buffer(salt),
            _from_buffer(personal) if personal is not None else ffi.NULL,
        ),
    )
    return binary_type(buf)


def crypto_generichash_blake2b_init_salt_personal(
    key,
    salt,
    personal=None,
    outlen=crypto_generichash_blake2b_BYTES,
):
    _assert_len(
        'key',
        key,
        crypto_generichash_blake2b_KEYBYTES_MIN,
        crypto_generichash_blake2b_KEYBYTES_MAX,
    )
    _assert_len('salt', salt, crypto_generichash_blake2b_SALTBYTES)

    if personal is not None:
        _assert_len(
            'personal',
            personal,
            crypto_generichash_blake2b_PERSONALBYTES,
        )

    assert crypto_generichash_blake2b_BYTES_MIN <= outlen <= \
        crypto_generichash_blake2b_BYTES_MAX, (
            "outlen must be between %d and %d" % (
                crypto_generichash_blake2b_BYTES_MIN,
                crypto_generichash_blake2b_BYTES_MAX,
            )
        )

    state = bytearray(crypto_generichash_STATEBYTES)

    _raise_on_error(
        lib.crypto_generichash_blake2b_init_salt_personal(
            ffi.cast(
                'crypto_generichash_blake2b_state *',
                ffi.from_buffer(state)
            ),
            _from_buffer(key),
            len(key),
            outlen,
            _from_buffer(salt),
            _from_buffer(personal) if personal is not None else ffi.NULL,
        ),
    )
    return state


# crypto_sign family
crypto_sign_BYTES = lib.crypto_sign_bytes()
"""Extra bytes needed for signature for crypto_sign_*"""
crypto_sign_SEEDBYTES = lib.crypto_sign_seedbytes()
"""Length of seed for :py:func:`crypto_sign_seed_keypair` in bytes"""
crypto_sign_PUBLICKEYBYTES = lib.crypto_sign_publickeybytes()
"""Length of Public key for crypto_sign_* in bytes"""
crypto_sign_SECRETKEYBYTES = lib.crypto_sign_secretkeybytes()
"""Length of secret key for crypto_sign_* in bytes"""


def crypto_sign_keypair():
    """Generate a random Public/Secret keypair for Public Key Signing

    libsodium documentation:
    `Public-key Signatures
    <https://download.libsodium.org/doc/
    public-key_cryptography/public-key_signatures.html
    #key-pair-generation>`__

    Returns:
        (:obj:`bytes`, :obj:`bytes`): 2-Element Tuple containing

        - **pk** (:obj:`bytes`): Public key of length
          :py:const:`crypto_sign_PUBLICKEYBYTES`
        - **sk** (:obj:`bytes`): Secret key of length
          :py:const:`crypto_sign_SECRETKEYBYTES`
    """
    pk = bytearray(crypto_sign_PUBLICKEYBYTES)
    sk = bytearray(crypto_sign_SECRETKEYBYTES)
    _raise_on_error(
        lib.crypto_sign_keypair(
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(pk), binary_type(sk)


def crypto_sign_seed_keypair(seed):
    """Generate a Public/Secret keypair from a seed for Public Key Signing

    libsodium documentation:
    `Public-key Signatures
    <https://download.libsodium.org/doc/
    public-key_cryptography/public-key_signatures.html
    #key-pair-generation>`__

    Args:
        seed (:any:`bytes-like<bytes-like object>`): Seed of length
            :py:const:`crypto_sign_SEEDBYTES`

    Returns:
        (:obj:`bytes`, :obj:`bytes`): 2-Element Tuple containing

        - **pk** (:obj:`bytes`): Public key of length
          :py:const:`crypto_sign_PUBLICKEYBYTES`
        - **sk** (:obj:`bytes`): Secret key of length
          :py:const:`crypto_sign_SECRETKEYBYTES`
    """
    _assert_len('seed', seed, crypto_sign_SEEDBYTES)

    pk = bytearray(crypto_sign_PUBLICKEYBYTES)
    sk = bytearray(crypto_sign_SECRETKEYBYTES)
    _raise_on_error(
        lib.crypto_sign_seed_keypair(
            _from_buffer(pk),
            _from_buffer(sk),
            _from_buffer(seed),
        ),
    )

    return binary_type(pk), binary_type(sk)


def crypto_sign(msg, sk):
    """Sign a message using Public Key Signing

    libsodium documentation:
    `Public-key Signatures
    <https://download.libsodium.org/doc/
    public-key_cryptography/public-key_signatures.html
    #combined-mode>`__

    Args:
        msg (:any:`bytes-like<bytes-like object>`): Message to sign
        sk (:any:`bytes-like<bytes-like object>`): Secret-key to sign message
            with of length :py:const:`crypto_sign_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: The combined message and signature of length *len(msg)* +
        :py:const:`crypto_sign_BYTES`
    """
    _assert_len('sk', sk, crypto_sign_SECRETKEYBYTES)

    signed_msg = bytearray(crypto_sign_BYTES + len(msg))
    _raise_on_error(
        lib.crypto_sign(
            _from_buffer(signed_msg),
            ffi.NULL,
            _from_buffer(msg),
            len(msg),
            _from_buffer(sk),
        ),
    )

    return binary_type(signed_msg)


def crypto_sign_open(signed_msg, pk):
    """Verify and return a signed message using Public Key Signing

    libsodium documentation:
    `Public-key Signatures
    <https://download.libsodium.org/doc/
    public-key_cryptography/public-key_signatures.html
    #combined-mode>`__

    Args:
        signed_msg (:any:`bytes-like<bytes-like object>`): Combined message
            and signature of length at least  :py:const:`crypto_sign_BYTES`
        pk (:any:`bytes-like<bytes-like object>`): Public key to verify signed
            message of length :py:const:`crypto_sign_BYTES`

    Returns:
        :obj:`bytes`: The message that was signed

    Raises:
        ValueError: Error in verifying signature
    """

    _assert_min_len('signed_msg', signed_msg, crypto_sign_BYTES)
    _assert_len('pk', pk, crypto_sign_PUBLICKEYBYTES)

    msg = bytearray(len(signed_msg) - crypto_sign_BYTES)
    _raise_on_error(
        lib.crypto_sign_open(
            _from_buffer(msg),
            ffi.NULL,
            _from_buffer(signed_msg),
            len(signed_msg),
            _from_buffer(pk),
        ),
    )

    return binary_type(msg)


def crypto_sign_detached(msg, sk):
    """Return a signature of a message using Public Key Signing

    libsodium documentation:
    `Public-key Signatures
    <https://download.libsodium.org/doc/
    public-key_cryptography/public-key_signatures.html
    #detached-mode>`__

    Args:
        msg (:any:`bytes-like<bytes-like object>`): Message to sign
        sk (:any:`bytes-like<bytes-like object>`): Secret-key to sign message
            with of length :py:const:`crypto_sign_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: Signature of length :py:const:`crypto_sign_BYTES`
    """

    _assert_len('sk', sk, crypto_sign_SECRETKEYBYTES)

    sig = bytearray(crypto_sign_BYTES)
    _raise_on_error(
        lib.crypto_sign_detached(
            _from_buffer(sig),
            ffi.NULL,
            _from_buffer(msg),
            len(msg),
            _from_buffer(sk),
        ),
    )

    return binary_type(sig)


def crypto_sign_verify_detached(msg, sig, pk):
    """Verify a signed message using Public Key Signing

    libsodium documentation:
    `Public-key Signatures
    <https://download.libsodium.org/doc/
    public-key_cryptography/public-key_signatures.html
    #detached-mode>`__

    Args:
        msg (:any:`bytes-like<bytes-like object>`): Message that was signed
        sig (:any:`bytes-like<bytes-like object>`): Signature of length
            :py:const:`crypto_sign_BYTES`
        pk (:any:`bytes-like<bytes-like object>`): Public key to verify signed
            message of length :py:const:`crypto_sign_PUBLICKEYBYTES`

    Returns:
        True

    Raises:
        ValueError: Error in verifying signature
    """
    _assert_len('sig', sig, crypto_sign_BYTES)
    _assert_len('pk', pk, crypto_sign_PUBLICKEYBYTES)

    _raise_on_error(
        lib.crypto_sign_verify_detached(
            _from_buffer(sig),
            _from_buffer(msg),
            len(msg),
            _from_buffer(pk),
        ),
    )

    return True


# ed25519 sign specific functions
crypto_sign_ed25519_SEEDBYTES = lib.crypto_sign_ed25519_seedbytes()
"""Length of seed returned from :py:func:`crypto_sign_ed25519_sk_to_seed` in
bytes"""
crypto_sign_ed25519_PUBLICKEYBYTES = lib.crypto_sign_ed25519_publickeybytes()
"""Length of ed25519 Public Key in bytes"""
crypto_sign_ed25519_SECRETKEYBYTES = lib.crypto_sign_ed25519_secretkeybytes()
"""Length of ed25519 Secret Key in bytes"""
crypto_scalarmult_curve25519_BYTES = lib.crypto_scalarmult_curve25519_bytes()
"""Length of curve25519 Public/Secret Keys in bytes"""


def crypto_sign_ed25519_pk_to_curve25519(ed25519_pk):
    """Convert a ed25519 signing public key into a curve25519 encryption
    public key

    libsodium documentation:
    `Ed25519 to Curve25519
    <https://download.libsodium.org/doc/
    advanced/ed25519-curve25519.html
    #usage>`__

    Args:
        ed25519_pk (:any:`bytes-like<bytes-like object>`): An ed25519 signing
            public key of length :py:const:`crypto_sign_ed25519_PUBLICKEYBYTES`

    Returns:
        :obj:`bytes`: A curve25519 public key for encryption of length
        :py:const:`crypto_scalarmult_curve25519_BYTES`
    """
    _assert_len("ed25519_pk", ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES)
    curve25519_pk = bytearray(crypto_scalarmult_curve25519_BYTES)
    _raise_on_error(
        lib.crypto_sign_ed25519_pk_to_curve25519(
            _from_buffer(curve25519_pk),
            _from_buffer(ed25519_pk),
        ),
    )

    return binary_type(curve25519_pk)


def crypto_sign_ed25519_sk_to_curve25519(ed25519_sk):
    """Convert a ed25519 signing secret key into a curve25519 encryption
    secret key

    libsodium documentation:
    `Ed25519 to Curve25519
    <https://download.libsodium.org/doc/
    advanced/ed25519-curve25519.html
    #usage>`__

    Args:
        ed25519_sk (:any:`bytes-like<bytes-like object>`): An ed25519 signing
            secret key of length :py:const:`crypto_sign_ed25519_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: A curve25519 secret key for encryption of length
        :py:const:`crypto_scalarmult_curve25519_BYTES`
    """
    _assert_len("ed25519_sk", ed25519_sk, crypto_sign_ed25519_SECRETKEYBYTES)
    curve25519_sk = bytearray(crypto_scalarmult_curve25519_BYTES)
    _raise_on_error(
        lib.crypto_sign_ed25519_sk_to_curve25519(
            _from_buffer(curve25519_sk),
            _from_buffer(ed25519_sk),
        ),
    )

    return binary_type(curve25519_sk)


def crypto_sign_ed25519_sk_to_seed(sk):
    """Extract seed used to generate an ed25519 Secret Key

    libsodium documentation:
    `Public Key Signatures
    <https://download.libsodium.org/doc/
    public-key_cryptography/public-key_signatures.html
    #extracting-the-seed-and-the-public-key-from-the-secret-key>`__

    Args:
        sk (:any:`bytes-like<bytes-like object>`): An ed25519 signing secret
            key of length :py:const:`crypto_sign_ed25519_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: The seed used to generate the secret key of length
        :py:const:`crypto_sign_ed25519_SEEDBYTES`
    """
    _assert_len("sk", sk, crypto_sign_ed25519_SECRETKEYBYTES)
    seed = bytearray(crypto_sign_ed25519_SEEDBYTES)
    _raise_on_error(
        lib.crypto_sign_ed25519_sk_to_seed(
            _from_buffer(seed),
            _from_buffer(sk),
        ),
    )

    return binary_type(seed)


def crypto_sign_ed25519_sk_to_pk(sk):
    """Extract public key from an ed25519 Secret Key

    libsodium documentation:
    `Public Key Signatures
    <https://download.libsodium.org/doc/
    public-key_cryptography/public-key_signatures.html
    #extracting-the-seed-and-the-public-key-from-the-secret-key>`__

    Args:
        sk (:any:`bytes-like<bytes-like object>`): An ed25519 signing secret
            key of length :py:const:`crypto_sign_ed25519_SECRETKEYBYTES`

    Returns:
        :obj:`bytes`: The ed25519 public key of length
        :py:const:`crypto_sign_ed25519_PUBLICKEYBYTES`
    """
    _assert_len("sk", sk, crypto_sign_ed25519_SECRETKEYBYTES)
    pk = bytearray(crypto_sign_ed25519_PUBLICKEYBYTES)
    _raise_on_error(
        lib.crypto_sign_ed25519_sk_to_pk(
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(pk)

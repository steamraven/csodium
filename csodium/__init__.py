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
    buf = bytearray(size)
    lib.randombytes(_from_buffer(buf), size)
    return binary_type(buf)

# crypto_box family.
crypto_box_BEFORENMBYTES = lib.crypto_box_beforenmbytes()
crypto_box_MACBYTES = lib.crypto_box_macbytes()
crypto_box_NONCEBYTES = lib.crypto_box_noncebytes()
crypto_box_PUBLICKEYBYTES = lib.crypto_box_publickeybytes()
crypto_box_SEALBYTES = lib.crypto_box_sealbytes()
crypto_box_SECRETKEYBYTES = lib.crypto_box_secretkeybytes()
crypto_box_SEEDBYTES = lib.crypto_box_seedbytes()


def crypto_box_keypair():
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
crypto_secretbox_NONCEBYTES = lib.crypto_secretbox_noncebytes()
crypto_secretbox_MACBYTES = lib.crypto_secretbox_macbytes()
crypto_secretbox_ZEROBYTES = lib.crypto_secretbox_zerobytes()
crytpo_secretbox_BOXZEROBYTES = lib.crypto_secretbox_boxzerobytes()


def crypto_secretbox(msg, nonce, k):
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


def crypto_secretbox_detached(msg, nonce, k):
    _assert_len('nonce', nonce, crypto_secretbox_NONCEBYTES)
    _assert_len('k', k, crypto_secretbox_KEYBYTES)

    c = bytearray(len(msg))
    mac = bytearray(crypto_secretbox_MACBYTES)
    _raise_on_error(
        lib.crypto_secretbox_detached(
            _from_buffer(c),
            _from_buffer(mac),
            _from_buffer(msg),
            len(msg),
            _from_buffer(nonce),
            _from_buffer(k),
        ),
    )

    return binary_type(c), binary_type(mac)


def crypto_secretbox_open_detached(c, mac, nonce, k):
    _assert_len('mac', mac, crypto_secretbox_MACBYTES)
    _assert_len('nonce', nonce, crypto_secretbox_NONCEBYTES)
    _assert_len('k', k, crypto_secretbox_KEYBYTES)

    msg = bytearray(len(c))
    _raise_on_error(
        lib.crypto_secretbox_open_detached(
            _from_buffer(msg),
            _from_buffer(c),
            _from_buffer(mac),
            len(c),
            _from_buffer(nonce),
            _from_buffer(k),
        ),
    )

    return binary_type(msg)

crypto_generichash_BYTES_MIN = lib.crypto_generichash_bytes_min()
crypto_generichash_BYTES_MAX = lib.crypto_generichash_bytes_max()
crypto_generichash_BYTES = lib.crypto_generichash_bytes()
crypto_generichash_KEYBYTES_MIN = lib.crypto_generichash_keybytes_min()
crypto_generichash_KEYBYTES_MAX = lib.crypto_generichash_keybytes_max()
crypto_generichash_KEYBYTES = lib.crypto_generichash_keybytes()
crypto_generichash_PRIMITIVE = lib.crypto_generichash_primitive()
crypto_generichash_STATEBYTES = lib.crypto_generichash_statebytes()


def crypto_generichash(in_, key, outlen=crypto_generichash_BYTES):
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
crypto_sign_SEEDBYTES = lib.crypto_sign_seedbytes()
crypto_sign_PUBLICKEYBYTES = lib.crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = lib.crypto_sign_secretkeybytes()


def crypto_sign_keypair():
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
crypto_sign_ed25519_PUBLICKEYBYTES = lib.crypto_sign_ed25519_publickeybytes()
crypto_sign_ed25519_SECRETKEYBYTES = lib.crypto_sign_ed25519_secretkeybytes()
crypto_scalarmult_curve25519_BYTES = lib.crypto_scalarmult_curve25519_bytes()


def crypto_sign_ed25519_pk_to_curve25519(ed25519_pk):
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
    _assert_len("sk", sk, crypto_sign_ed25519_SECRETKEYBYTES)
    pk = bytearray(crypto_sign_ed25519_PUBLICKEYBYTES)
    _raise_on_error(
        lib.crypto_sign_ed25519_sk_to_pk(
            _from_buffer(pk),
            _from_buffer(sk),
        ),
    )

    return binary_type(pk)

crypto_stream_KEYBYTES = lib.crypto_stream_keybytes()
crypto_stream_NONCEBYTES = lib.crypto_stream_noncebytes()


def crypto_stream(clen, nonce, k):
    _assert_len("nonce", nonce, crypto_stream_NONCEBYTES)
    _assert_len("k", k, crypto_stream_KEYBYTES)

    c = bytearray(clen)
    _raise_on_error(
        lib.crypto_stream(
            _from_buffer(c),
            clen,
            _from_buffer(nonce),
            _from_buffer(k)
        ),
    )

    return binary_type(c)


def crypto_stream_xor(msg, nonce, k):
    _assert_len("nonce", nonce, crypto_stream_NONCEBYTES)
    _assert_len("k", k, crypto_stream_KEYBYTES)

    mlen = len(msg)
    c = bytearray(mlen)
    _raise_on_error(
        lib.crypto_stream_xor(
            _from_buffer(c),
            _from_buffer(msg),
            mlen,
            _from_buffer(nonce),
            _from_buffer(k),
        ),
    )
    return binary_type(c)


crypto_stream_xsalsa20_KEYBYTES = lib.crypto_stream_xsalsa20_keybytes()
crypto_stream_xsalsa20_NONCEBYTES = lib.crypto_stream_xsalsa20_noncebytes()


def crypto_stream_xsalsa20_xor_ic(msg, nonce, ic, k):
    _assert_len("nonce", nonce, crypto_stream_xsalsa20_NONCEBYTES)
    _assert_len("k", k, crypto_stream_xsalsa20_KEYBYTES)

    mlen = len(msg)
    c = bytearray(mlen)
    _raise_on_error(
        lib.crypto_stream_xsalsa20_xor_ic(
            _from_buffer(c),
            _from_buffer(msg),
            mlen,
            _from_buffer(nonce),
            ic,
            _from_buffer(k),
        ),
    )

    return binary_type(c)

crypto_stream_salsa20_KEYBYTES = lib.crypto_stream_salsa20_keybytes()
crypto_stream_salsa20_NONCEBYTES = lib.crypto_stream_salsa20_noncebytes()


def crypto_stream_salsa20(clen, nonce, k):
    _assert_len("nonce", nonce, crypto_stream_salsa20_NONCEBYTES)
    _assert_len("k", k, crypto_stream_salsa20_KEYBYTES)

    c = bytearray(clen)
    _raise_on_error(
        lib.crypto_stream_salsa20(
            _from_buffer(c),
            clen,
            _from_buffer(nonce),
            _from_buffer(k),
        ),
    )

    return binary_type(c)


def crypto_stream_salsa20_xor(msg, nonce, k):
    _assert_len("nonce", nonce, crypto_stream_salsa20_NONCEBYTES)
    _assert_len("k", k, crypto_stream_salsa20_KEYBYTES)

    mlen = len(msg)
    c = bytearray(mlen)
    _raise_on_error(
        lib.crypto_stream_salsa20_xor(
            _from_buffer(c),
            _from_buffer(msg),
            mlen,
            _from_buffer(nonce),
            _from_buffer(k),
        ),
    )

    return binary_type(c)


def crypto_stream_salsa20_xor_ic(msg, nonce, ic, k):
    _assert_len("nonce", nonce, crypto_stream_salsa20_NONCEBYTES)
    _assert_len("k", k, crypto_stream_salsa20_KEYBYTES)

    mlen = len(msg)
    c = bytearray(mlen)
    _raise_on_error(
        lib.crypto_stream_salsa20_xor_ic(
            _from_buffer(c),
            _from_buffer(msg),
            mlen,
            _from_buffer(nonce),
            ic,
            _from_buffer(k),
        ),
    )

    return binary_type(c)

crypto_core_hsalsa20_OUTPUTBYTES = lib.crypto_core_hsalsa20_outputbytes()
crypto_core_hsalsa20_INPUTBYTES = lib.crypto_core_hsalsa20_inputbytes()
crypto_core_hsalsa20_KEYBYTES = lib.crypto_core_hsalsa20_keybytes()
crypto_core_hsalsa20_CONSTBYTES = lib.crypto_core_hsalsa20_constbytes()


def crypto_core_hsalsa20(in_, k, c):
    _assert_len("in_", in_, crypto_core_hsalsa20_INPUTBYTES)
    _assert_len("k", k, crypto_core_hsalsa20_KEYBYTES)
    if (c is not None or
            SODIUM_VERSION < (1, 0, 9)):  # pragma: no cover
        _assert_len("c", c, crypto_core_hsalsa20_CONSTBYTES)

    out = bytearray(crypto_core_hsalsa20_OUTPUTBYTES)
    _raise_on_error(
        lib.crypto_core_hsalsa20(
            _from_buffer(out),
            _from_buffer(in_),
            _from_buffer(k),
            _from_buffer(c) if c is not None else ffi.NULL,
        ),
    ),

    return binary_type(out)

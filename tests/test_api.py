"""
Test the whole exposed API.
"""

import pytest

from six import binary_type

from csodium import (
    SODIUM_VERSION,
    crypto_box,
    crypto_box_BEFORENMBYTES,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_box_SEEDBYTES,
    crypto_box_afternm,
    crypto_box_beforenm,
    crypto_box_detached,
    crypto_box_keypair,
    crypto_box_open,
    crypto_box_open_afternm,
    crypto_box_open_detached,
    crypto_box_seal,
    crypto_box_seal_open,
    crypto_box_seed_keypair,
    crypto_secretbox,
    crypto_secretbox_open,
    crypto_secretbox_detached,
    crypto_secretbox_open_detached,
    randombytes,
    crypto_generichash_BYTES,
    crypto_generichash_STATEBYTES,
    crypto_generichash,
    crypto_generichash_init,
    crypto_generichash_update,
    crypto_generichash_final,
    crypto_generichash_blake2b_BYTES,
    crypto_generichash_blake2b_salt_personal,
    crypto_generichash_blake2b_init_salt_personal,
    crypto_sign_BYTES,
    crypto_sign_SEEDBYTES,
    crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES,
    crypto_sign_keypair,
    crypto_sign_seed_keypair,
    crypto_sign,
    crypto_sign_open,
    crypto_sign_detached,
    crypto_sign_verify_detached,
    crypto_sign_ed25519_PUBLICKEYBYTES,
    crypto_sign_ed25519_SECRETKEYBYTES,
    crypto_sign_ed25519_SEEDBYTES,
    crypto_scalarmult_curve25519_BYTES,
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519,
    crypto_sign_ed25519_sk_to_seed,
    crypto_sign_ed25519_sk_to_pk,
    crypto_stream,
    crypto_stream_xor,
    crypto_stream_xsalsa20_xor_ic,
    crypto_stream_salsa20,
    crypto_stream_salsa20_xor,
    crypto_stream_salsa20_xor_ic,
    crypto_core_hsalsa20_INPUTBYTES,
    crypto_core_hsalsa20_OUTPUTBYTES,
    crypto_core_hsalsa20,
)


def optional_kw(**kwargs):
    return dict((i for i in kwargs.items() if i[1] is not None))


@pytest.fixture
def bad():
    return b''


@pytest.fixture
def pk():
    pk, _ = crypto_box_seed_keypair(b'x' * crypto_box_SEEDBYTES)
    return pk


@pytest.fixture
def sk():
    _, sk = crypto_box_seed_keypair(b'x' * crypto_box_SEEDBYTES)
    return sk


@pytest.fixture
def nonce8():
    return b'x' * 8


@pytest.fixture
def nonce24():
    return b'x' * 24


@pytest.fixture
def k():
    pk, sk = crypto_box_seed_keypair(b'x' * crypto_box_SEEDBYTES)
    return crypto_box_beforenm(pk=pk, sk=sk)


@pytest.fixture
def mac16():
    return b'x' * 16


@pytest.fixture
def state():
    return crypto_generichash_init(None)


@pytest.fixture
def key32():
    return b'x' * 32


@pytest.fixture
def salt16():
    return b'x' * 16


@pytest.fixture
def personal16():
    return b'x' * 16


@pytest.fixture
def sign_pk():
    pk, _ = crypto_sign_seed_keypair(b'x' * crypto_sign_SEEDBYTES)
    return pk


@pytest.fixture
def sign_sk():
    _, sk = crypto_sign_seed_keypair(b'x' * crypto_sign_SEEDBYTES)
    return sk


@pytest.fixture
def sig():
    return b'x' * crypto_sign_BYTES


def test_version():
    # There is nothing much we can test here.
    assert len(SODIUM_VERSION) == 3

    for x in SODIUM_VERSION:
        assert isinstance(x, int)


def test_randombytes():
    b = randombytes(4)
    assert len(b) == 4


def test_crypto_box_keypair():
    pk, sk = crypto_box_keypair()
    assert len(pk) == crypto_box_PUBLICKEYBYTES
    assert len(sk) == crypto_box_SECRETKEYBYTES


def test_crypto_box_seed_keypair_invalid_seed():
    with pytest.raises(AssertionError):
        crypto_box_seed_keypair(b'invalid')


def test_crypto_box_seed_keypair():
    pk, sk = crypto_box_seed_keypair(b'x' * crypto_box_SEEDBYTES)
    assert len(pk) == crypto_box_PUBLICKEYBYTES
    assert len(sk) == crypto_box_SECRETKEYBYTES


@pytest.mark.parametrize(" pk,    sk",
                         [(bad(), sk()),
                          (pk(),  bad())],
                         ids=['invalid_pk', 'invalid_sk'])
def test_crypto_box_beforenm_assert(pk, sk):
    with pytest.raises(AssertionError):
        crypto_box_beforenm(
            pk=pk,
            sk=sk,
        )


def test_crypto_box_beforenm(pk, sk):
    k = crypto_box_beforenm(
        pk=pk,
        sk=sk,
    )
    assert len(k) == crypto_box_BEFORENMBYTES


@pytest.mark.parametrize(" nonce24,   pk,    sk",
                         [(bad(),     pk(),  sk()),
                          (nonce24(), bad(), sk()),
                          (nonce24(), pk(),  bad())],
                         ids=['invalid_nonce', 'invalid_pk', 'invalid_sk'])
def test_crypto_box_assert(nonce24, pk, sk):
    with pytest.raises(AssertionError):
        crypto_box(
            msg=b'foo',
            nonce=nonce24,
            pk=pk,
            sk=sk,
        )


def test_crypto_box(sk, pk, nonce24):
    c = crypto_box(
        msg=b'foo',
        nonce=nonce24,
        pk=pk,
        sk=sk,
    )
    assert isinstance(c, binary_type)


@pytest.mark.parametrize(" nonce24,   k",
                         [(bad(),     k()),
                          (nonce24(), bad())],
                         ids=['invalid_nonce', 'invalid_k'])
def test_crypto_box_afternm_assert(nonce24, k):
    with pytest.raises(AssertionError):
        crypto_box_afternm(
            msg=b'foo',
            nonce=nonce24,
            k=k,
        )


def test_crypto_box_afternm(nonce24, k):
    c = crypto_box_afternm(
        msg=b'foo',
        nonce=nonce24,
        k=k,
    )
    assert isinstance(c, binary_type)


@pytest.mark.parametrize(" nonce24,   pk,    sk",
                         [(bad(),     pk(),  sk()),
                          (nonce24(), bad(), sk()),
                          (nonce24(), pk(),  bad())],
                         ids=['invalid_nonce', 'invalid_pk', 'invalid_sk'])
def test_crypto_box_open_assert(nonce24, pk, sk):
    with pytest.raises(AssertionError):
        crypto_box_open(
            c=b'x' * 100,
            nonce=nonce24,
            pk=pk,
            sk=sk,
        )


def test_crypto_box_open_failure(nonce24, pk, sk):
    with pytest.raises(ValueError):
        crypto_box_open(
            c=b'x' * 100,
            nonce=nonce24,
            pk=pk,
            sk=sk,
        )


def test_crypto_box_open(nonce24, pk, sk):
    c = crypto_box(
        msg=b'foo',
        nonce=nonce24,
        pk=pk,
        sk=sk,
    )
    msg = crypto_box_open(
        c=c,
        nonce=nonce24,
        pk=pk,
        sk=sk,
    )
    assert msg == b'foo'


@pytest.mark.parametrize(" nonce24,   k",
                         [(bad(),     k()),
                          (nonce24(), bad())],
                         ids=['invalid_nonce', 'invalid_k'])
def test_crypto_box_open_afternm_assert(nonce24, k):
    with pytest.raises(AssertionError):
        crypto_box_open_afternm(
            c=b'x' * 100,
            nonce=nonce24,
            k=k,
        )


def test_crypto_box_open_afternm(nonce24, k):
    c = crypto_box_afternm(
        msg=b'foo',
        nonce=nonce24,
        k=k,
    )
    msg = crypto_box_open_afternm(
        c=c,
        nonce=nonce24,
        k=k,
    )
    assert msg == b'foo'


def test_crypto_box_seal_invalid_pk():
    with pytest.raises(AssertionError):
        crypto_box_seal(
            msg=b'foo',
            pk=b'',
        )


def test_crypto_box_seal(pk):
    c = crypto_box_seal(
        msg=b'foo',
        pk=pk,
    )
    assert isinstance(c, binary_type)


@pytest.mark.parametrize(" pk,    sk",
                         [(bad(), sk()),
                          (pk(),  bad())],
                         ids=['invalid_pk', 'invalid_sk'])
def test_crypto_box_seal_open_assert(pk, sk):
    with pytest.raises(AssertionError):
        crypto_box_seal_open(
            c=b'',
            pk=pk,
            sk=sk,
        )


def test_crypto_box_seal_open_failure(pk, sk):
    with pytest.raises(ValueError):
        crypto_box_seal_open(
            c=b'x' * 100,
            pk=pk,
            sk=sk,
        )


def test_crypto_box_seal_open(pk, sk):
    c = crypto_box_seal(
        msg=b'foo',
        pk=pk,
    )
    msg = crypto_box_seal_open(
        c=c,
        pk=pk,
        sk=sk,
    )
    assert msg == b'foo'


@pytest.mark.parametrize(" nonce24,   pk,    sk",
                         [(bad(),     pk(),  sk()),
                          (nonce24(), bad(), sk()),
                          (nonce24(), pk(),  bad())],
                         ids=['invalid_nonce', 'invalid_pk', 'invalid_sk'])
def test_crypto_box_detached_assert(nonce24, pk, sk):
    with pytest.raises(AssertionError):
        crypto_box_detached(
            msg=b'foo',
            nonce=nonce24,
            pk=pk,
            sk=sk,
        )


def test_crypto_box_detached(nonce24, pk, sk):
    c, mac = crypto_box_detached(
        msg=b'foo',
        nonce=nonce24,
        pk=pk,
        sk=sk,
    )
    assert isinstance(c, binary_type)
    assert isinstance(mac, binary_type)


@pytest.mark.parametrize(" mac16,   nonce24,   pk,    sk",
                         [(bad(),   nonce24(), pk(),  sk()),
                          (mac16(), bad(),     pk(),  sk()),
                          (mac16(), nonce24(), bad(), sk()),
                          (mac16(), nonce24(), pk(),  bad())],
                         ids=['invalid_mac', 'invalid_nonce', 'invalid_pk',
                              'invalid_sk'])
def test_crypto_box_open_detached_assert(mac16, nonce24, pk, sk):
    with pytest.raises(AssertionError):
        crypto_box_open_detached(
            c=b'',
            mac=mac16,
            nonce=nonce24,
            pk=pk,
            sk=sk,
        )


def test_crypto_box_open_detached_failure(mac16, nonce24, pk, sk):
    with pytest.raises(ValueError):
        crypto_box_open_detached(
            c=b'x' * 100,
            mac=mac16,
            nonce=nonce24,
            pk=pk,
            sk=sk,
        )


def test_crypto_box_open_detached(nonce24, pk, sk):
    c, mac = crypto_box_detached(
        msg=b'foo',
        nonce=nonce24,
        pk=pk,
        sk=sk,
    )
    msg = crypto_box_open_detached(
        c=c,
        mac=mac,
        nonce=nonce24,
        pk=pk,
        sk=sk,
    )
    assert msg == b'foo'


@pytest.mark.parametrize(" nonce24,   key32",
                         [(bad(),     key32()),
                          (nonce24(), bad())],
                         ids=['invalid_nonce', 'invalid_key'])
def test_crypto_secretbox_assert(nonce24, key32):
    with pytest.raises(AssertionError):
        crypto_secretbox(
            msg=b'foo',
            nonce=nonce24,
            k=key32,
        )


def test_crypto_secretbox(nonce24, key32):
    c = crypto_secretbox(
        msg=b'foo',
        nonce=nonce24,
        k=key32,
    )
    assert isinstance(c, binary_type)


@pytest.mark.parametrize(" nonce24,   key32",
                         [(bad(),     key32()),
                          (nonce24(), bad())],
                         ids=['invalid_nonce', 'invalid_key'])
def test_crypto_secretbox_open_assert(nonce24, key32):
    with pytest.raises(AssertionError):
        crypto_secretbox_open(
            c=b'',
            nonce=nonce24,
            k=key32,
        )


def test_crypto_secretbox_open_failure(nonce24, key32):
    with pytest.raises(ValueError):
        crypto_secretbox_open(
            c=b'x' * 100,
            nonce=nonce24,
            k=key32,
        )


def test_crypto_secretbox_open(nonce24, key32):
    c = crypto_secretbox(
        msg=b'foo',
        nonce=nonce24,
        k=key32,
    )
    msg = crypto_secretbox_open(
        c=c,
        nonce=nonce24,
        k=key32,
    )
    assert msg == b'foo'


@pytest.mark.parametrize(" nonce24,   key32",
                         [(bad(),     key32()),
                          (nonce24(), bad())],
                         ids=['invalid_nonce', 'invalid_key'])
def test_crypto_secretbox_detached_assert(nonce24, key32):
    with pytest.raises(AssertionError):
        crypto_secretbox_detached(
            msg=b'foo',
            nonce=nonce24,
            k=key32,
        )


def test_crypto_secretbox_detached(nonce24, key32):
    c, mac = crypto_secretbox_detached(
        msg=b'foo',
        nonce=nonce24,
        k=key32,
    )
    assert isinstance(c, binary_type)
    assert isinstance(mac, binary_type)


@pytest.mark.parametrize(" mac16,   nonce24,   key32",
                         [(bad(),   nonce24(), key32()),
                          (mac16(), bad(),     key32()),
                          (mac16(), nonce24(), bad())],
                         ids=['invalid_mac', 'invalid_nonce', 'invalid_key'])
def test_crypto_secretbox_open_detached_assert(mac16, nonce24, key32):
    with pytest.raises(AssertionError):
        crypto_secretbox_open_detached(
            c=b'',
            mac=mac16,
            nonce=nonce24,
            k=key32,
        )


def test_crypto_secretbox_open_detached_failure(mac16, nonce24, key32):
    with pytest.raises(ValueError):
        crypto_secretbox_open_detached(
            c=b'',
            mac=mac16,
            nonce=nonce24,
            k=key32,
        )


def test_crypto_secretbox_open_detached(nonce24, key32):
    c, mac = crypto_secretbox_detached(
        msg=b'foo',
        nonce=nonce24,
        k=key32,
    )
    msg = crypto_secretbox_open_detached(
        c=c,
        mac=mac,
        nonce=nonce24,
        k=key32,
    )
    assert msg == b'foo'


@pytest.mark.parametrize(" key32,   outlen",
                         [(b'1',    None),
                          (key32(), 1)],
                         ids=['key_too_short', 'invalid_outlen'])
def test_crypto_generichash_assert(key32, outlen):
    with pytest.raises(AssertionError):
        crypto_generichash(
            in_=b'x',
            key=key32,
            **optional_kw(outlen=outlen)
        )


@pytest.mark.parametrize(" in_,  key32,   outlen",
                         [(b'x', None,    None),
                          (None, key32(), None),
                          (b'x', key32(), None),
                          (b'x', key32(), 35)],
                         ids=['null_key', 'null_in', 'normal', 'outlen'])
def test_crypto_generichash(in_, key32, outlen):
    out = crypto_generichash(
        in_=in_,
        key=key32,
        **optional_kw(outlen=outlen)
    )
    assert isinstance(out, binary_type)
    assert len(out) == crypto_generichash_BYTES if outlen is None else outlen


@pytest.mark.parametrize(" key32,   outlen",
                         [(bad(),    None),
                          (key32(), 1)],
                         ids=['key_too_short', 'invalid_outlen'])
def test_crypto_generichash_init_assert(key32, outlen):
    with pytest.raises(AssertionError):
        crypto_generichash_init(
            key=key32,
            **optional_kw(outlen=outlen)
        )


@pytest.mark.parametrize(" key32,   outlen",
                         [(None,    None),
                          (key32(), None),
                          (key32(), 35)],
                         ids=['null_key', 'normal', 'outlen'])
def test_crypto_generichash_init(key32, outlen):
    out = crypto_generichash_init(
        key=key32,
        **optional_kw(outlen=outlen)
    )
    assert isinstance(out, bytearray)
    assert len(out) == crypto_generichash_STATEBYTES


def test_crypto_generichash_update_state_too_short():
    with pytest.raises(AssertionError):
        crypto_generichash_update(
            state=b'1',
            in_=b'x',
        )


def test_crypto_generichash_update(state):
    crypto_generichash_update(
        state=state,
        in_=b'x',
    )


@pytest.mark.parametrize(" state,   outlen",
                         [(bad(),    None),
                          (state(), 1)],
                         ids=['state_too_short', 'invalid_outlen'])
def test_crypto_generichash_final_assert(state, outlen):
    with pytest.raises(AssertionError):
        crypto_generichash_final(
            state=state,
            **optional_kw(outlen=outlen)
        )


@pytest.mark.parametrize(" outlen",
                         [None,
                          35],
                         ids=['normal', 'outlen'])
def test_crypto_generichash_final(state, outlen):
    out = crypto_generichash_final(
        state=state,
        **optional_kw(outlen=outlen)
    )
    assert isinstance(out, binary_type)
    assert len(out) == crypto_generichash_BYTES if outlen is None else outlen


@pytest.mark.parametrize(" key32,   salt16,   personal16,   outlen",
                         [(bad(),   salt16(), None,         None),
                          (key32(), bad(),    None,         None),
                          (key32(), salt16(), bad(),        None),
                          (key32(), salt16(), personal16(), 1)],
                         ids=['key_too_short', 'salt_too_short',
                              'personal_too_short', 'invalid_outlen'])
def test_crypto_generichash_blake2b_salt_assert(
    key32,
    salt16,
    personal16,
    outlen
):
    with pytest.raises(AssertionError):
        crypto_generichash_blake2b_salt_personal(
            in_=None,
            key=key32,
            salt=salt16,
            **optional_kw(
                personal=personal16,
                outlen=outlen
            )
        )


@pytest.mark.parametrize(" personal16,   outlen",
                         [(personal16(), None),
                          (None,         None),
                          (None,         35)],
                         ids=['personal', 'normal', 'outlen'])
def test_crypto_generichash_blake2b_salt(key32, salt16, personal16, outlen):
    out = crypto_generichash_blake2b_salt_personal(
        in_=None,
        key=key32,
        salt=salt16,
        **optional_kw(
            personal=personal16,
            outlen=outlen
        )
    )
    assert isinstance(out, binary_type)
    assert len(out) == (crypto_generichash_blake2b_BYTES
                        if outlen is None else outlen)


@pytest.mark.parametrize(" key32,   salt16,   personal16,   outlen",
                         [(bad(),   salt16(), None,         None),
                          (key32(), bad(),    None,         None),
                          (key32(), salt16(), bad(),        None),
                          (key32(), salt16(), personal16(), 1)],
                         ids=['key_too_short', 'salt_too_short',
                              'personal_too_short', 'invalid_outlen'])
def test_crypto_generichash_blake2b_init_salt_assert(
    key32,
    salt16,
    personal16,
    outlen
):
    with pytest.raises(AssertionError):
        crypto_generichash_blake2b_init_salt_personal(
            key=key32,
            salt=salt16,
            **optional_kw(
                personal=personal16,
                outlen=outlen
            )
        )


@pytest.mark.parametrize(" personal16,   outlen",
                         [(None,         None),
                          (personal16(), None),
                          (None,         35)],
                         ids=['normal', 'personal', 'outlen'])
def test_crypto_generichash_blake2b_init_salt(
    key32,
    salt16,
    personal16,
    outlen
):
    out = crypto_generichash_blake2b_init_salt_personal(
        key=key32,
        salt=salt16,
        **optional_kw(
            personal=personal16,
            outlen=outlen
        )
    )
    assert isinstance(out, bytearray)
    assert len(out) == crypto_generichash_STATEBYTES


def test_crypto_sign_keypair():
    pk, sk = crypto_sign_keypair()
    assert len(pk) == crypto_sign_PUBLICKEYBYTES
    assert len(sk) == crypto_sign_SECRETKEYBYTES


def test_crypto_sign_seed_keypair_invalid_seed():
    with pytest.raises(AssertionError):
        crypto_sign_seed_keypair(b'invalid')


def test_crypto_sign_seed_keypair():
    pk, sk = crypto_sign_seed_keypair(b'x' * crypto_sign_SEEDBYTES)
    assert len(pk) == crypto_sign_PUBLICKEYBYTES
    assert len(sk) == crypto_sign_SECRETKEYBYTES


def test_crypto_sign_invalid_sk():
    with pytest.raises(AssertionError):
        crypto_sign(
            msg=b'foo',
            sk=b'',
        )


def test_crypto_sign(sign_sk):
    msg = b'foo'
    signed_msg = crypto_sign(
        msg=msg,
        sk=sign_sk,
    )
    assert isinstance(signed_msg, binary_type)
    assert len(signed_msg) == len(msg) + crypto_sign_BYTES


def test_crypto_sign_open_invalid_pk():
    with pytest.raises(AssertionError):
        crypto_sign_open(
            signed_msg=b'x' * 100,
            pk=b'',
        )


def test_crypto_sign_open_failure(sign_pk):
    with pytest.raises(ValueError):
        crypto_sign_open(
            signed_msg=b'x' * 100,
            pk=sign_pk,
        )


def test_crypto_sign_open(sign_pk, sign_sk):
    signed_msg = crypto_sign(
        msg=b'foo',
        sk=sign_sk,
    )
    msg = crypto_sign_open(
        signed_msg=signed_msg,
        pk=sign_pk,
    )
    assert msg == b'foo'


def test_crypto_sign_detached_invalid_sk():
    with pytest.raises(AssertionError):
        crypto_sign_detached(
            msg=b'foo',
            sk=b'',
        )


def test_crypto_sign_detached(sign_sk):
    sig = crypto_sign_detached(
        msg=b'foo',
        sk=sign_sk,
    )
    assert isinstance(sig, binary_type)
    assert len(sig) == crypto_sign_BYTES


@pytest.mark.parametrize(' sig,   sign_pk',
                         [(bad(), sign_pk()),
                          (sig(), bad())],
                         ids=['invalid_sig', 'invalid_pk'])
def test_crypto_sign_verify_detached_assert(sig, sign_pk):
    with pytest.raises(AssertionError):
        crypto_sign_verify_detached(
            msg=b'',
            sig=sig,
            pk=sign_pk,
        )


def test_crypto_sign_verify_detached_failure(sig, sign_pk):
    with pytest.raises(ValueError):
        crypto_sign_verify_detached(
            msg=b'',
            sig=sig,
            pk=sign_pk,
        )


def test_crypto_sign_verify_detached(sign_pk, sign_sk):
    msg = b'foo'
    sig = crypto_sign_detached(
        msg=msg,
        sk=sign_sk,
    )
    result = crypto_sign_verify_detached(
        msg=msg,
        sig=sig,
        pk=sign_pk,
    )
    assert result is True


def test_crypto_sign_ed25519_pk_to_curve25519_invalid_pk():
    with pytest.raises(AssertionError):
        crypto_sign_ed25519_pk_to_curve25519(b'invalid')


def test_crypto_sign_ed25519_pk_to_curve25519():
    curve_pk = crypto_sign_ed25519_pk_to_curve25519(
        b'x' * crypto_sign_ed25519_PUBLICKEYBYTES
    )
    assert len(curve_pk) == crypto_scalarmult_curve25519_BYTES


def test_crypto_sign_ed25519_sk_to_curve25519_invalid_sk():
    with pytest.raises(AssertionError):
        crypto_sign_ed25519_sk_to_curve25519(b'invalid')


def test_crypto_sign_ed25519_sk_to_curve25519():
    curve_sk = crypto_sign_ed25519_sk_to_curve25519(
        b'x' * crypto_sign_ed25519_SECRETKEYBYTES
    )
    assert len(curve_sk) == crypto_scalarmult_curve25519_BYTES


def test_crypto_sign_ed25519_sk_to_seed_invalid_sk():
    with pytest.raises(AssertionError):
        crypto_sign_ed25519_sk_to_seed(b'invalid')


def test_crypto_sign_ed25519_sk_to_seed():
    seed = crypto_sign_ed25519_sk_to_seed(
        b'x' * crypto_sign_ed25519_SECRETKEYBYTES
    )
    assert len(seed) == crypto_sign_ed25519_SEEDBYTES


def test_crypto_sign_ed25519_sk_to_pk_invalid_sk():
    with pytest.raises(AssertionError):
        crypto_sign_ed25519_sk_to_pk(b'invalid')


def test_crypto_sign_ed25519_sk_to_pk():
    pk = crypto_sign_ed25519_sk_to_pk(
        b'x' * crypto_sign_ed25519_SECRETKEYBYTES
    )
    assert len(pk) == crypto_sign_ed25519_PUBLICKEYBYTES


@pytest.mark.parametrize(' nonce24,   key32',
                         [(bad(),     key32()),
                          (nonce24(), bad())],
                         ids=['invalid_nonce', 'invalid_key'])
def test_crypto_stream_assert(nonce24, key32):
    with pytest.raises(AssertionError):
        crypto_stream(
            clen=10,
            nonce=nonce24,
            k=key32,
        )


def test_crypto_stream(nonce24, key32):
    c = crypto_stream(
        clen=10,
        nonce=nonce24,
        k=key32,
    )
    assert isinstance(c, binary_type)
    assert len(c) == 10


@pytest.mark.parametrize(' nonce24,   key32',
                         [(bad(),     key32()),
                          (nonce24(), bad())],
                         ids=['invalid_nonce', 'invalid_key'])
def test_crypto_stream_xor_assert(nonce24, key32):
    with pytest.raises(AssertionError):
        crypto_stream_xor(
            msg=b'hello',
            nonce=nonce24,
            k=key32,
        )


def test_crypto_stream_xor(nonce24, key32):
    c = crypto_stream_xor(
        msg=b'foo',
        nonce=nonce24,
        k=key32,
    )
    msg = crypto_stream_xor(
        msg=c,
        nonce=nonce24,
        k=key32,
    )
    assert msg == b'foo'


@pytest.mark.parametrize(' nonce24,   key32',
                         [(bad(),     key32()),
                          (nonce24(), bad())],
                         ids=['invalid_nonce', 'invalid_key'])
def test_crypto_stream_xsalsa20_xor_ic_assert(nonce24, key32):
    with pytest.raises(AssertionError):
        crypto_stream_xsalsa20_xor_ic(
            msg=b'hello',
            nonce=nonce24,
            ic=0,
            k=key32,
        )


def test_crypto_stream_xsalsa20_xor_ic(nonce24, key32):
    c = crypto_stream_xsalsa20_xor_ic(
        msg=b'foo',
        nonce=nonce24,
        ic=0,
        k=key32,
    )
    msg = crypto_stream_xsalsa20_xor_ic(
        msg=c,
        nonce=nonce24,
        ic=0,
        k=key32,
    )
    assert msg == b'foo'


@pytest.mark.parametrize(' nonce8,   key32',
                         [(bad(),    key32()),
                          (nonce8(), bad())],
                         ids=['invalid_nonce', 'invalid_key'])
def test_crypto_stream_salsa20_invalid_nonce(nonce8, key32):
    with pytest.raises(AssertionError):
        crypto_stream_salsa20(
            clen=10,
            nonce=nonce8,
            k=key32,
        )


def test_crypto_stream_salsa20(nonce8, key32):
    c = crypto_stream_salsa20(
        clen=10,
        nonce=nonce8,
        k=key32,
    )

    assert isinstance(c, binary_type)
    assert len(c) == 10


@pytest.mark.parametrize(' nonce8,   key32',
                         [(bad(),    key32()),
                          (nonce8(), bad())],
                         ids=['invalid_nonce', 'invalid_key'])
def test_crypto_stream_salsa20_xor_assert(nonce8, key32):
    with pytest.raises(AssertionError):
        crypto_stream_salsa20_xor(
            msg=b'hello',
            nonce=nonce8,
            k=key32,
        )


def test_crypto_stream_salsa20_xor(nonce8, key32):
    c = crypto_stream_salsa20_xor(
        msg=b'foo',
        nonce=nonce8,
        k=key32,
    )
    msg = crypto_stream_salsa20_xor(
        msg=c,
        nonce=nonce8,
        k=key32,
    )
    assert msg == b'foo'


@pytest.mark.parametrize(' nonce8,   key32',
                         [(bad(),    key32()),
                          (nonce8(), bad())],
                         ids=['invalid_nonce', 'invalid_key'])
def test_crypto_stream_salsa20_xor_ic_assert(nonce8, key32):
    with pytest.raises(AssertionError):
        crypto_stream_salsa20_xor_ic(
            msg=b'hello',
            nonce=nonce8,
            ic=0,
            k=key32,
        )


def test_crypto_stream_salsa20_xor_ic(nonce8, key32):
    c = crypto_stream_salsa20_xor_ic(
        msg=b'foo',
        nonce=nonce8,
        ic=0,
        k=key32,
    )
    msg = crypto_stream_salsa20_xor_ic(
        msg=c,
        nonce=nonce8,
        ic=0,
        k=key32,
    )
    assert msg == b'foo'


@pytest.mark.parametrize(' in_,      key32,   const',
                         [(bad(),    key32(), salt16()),
                          (salt16(), bad(),   salt16()),
                          (salt16(), key32(), bad())],
                         ids=['invalid_in', 'invalid_key', 'invalid_const'])
def test_crypto_core_hsalsa20_assert(in_, key32, const):
    with pytest.raises(AssertionError):
        crypto_core_hsalsa20(
            in_=in_,
            k=key32,
            c=const,
        )


@pytest.mark.skipif(SODIUM_VERSION < (1, 0, 9),
                    reason="requires sodium 1.0.9")
def test_crypto_core_hsalsa20_null_c(key32):
    out = crypto_core_hsalsa20(
        in_=b'x' * crypto_core_hsalsa20_INPUTBYTES,
        k=key32,
        c=None,
    )
    assert isinstance(out, binary_type)
    assert len(out) == crypto_core_hsalsa20_OUTPUTBYTES


@pytest.mark.skipif(SODIUM_VERSION >= (1, 0, 9),
                    reason="fixed in sodium 1.0.9")
def test_crypto_core_hsalsa20_invalid_null_c(key32):
    with pytest.raises(AssertionError):
        crypto_core_hsalsa20(
            in_=b'x' * crypto_core_hsalsa20_INPUTBYTES,
            k=key32,
            c=None,
        )


def test_crypto_core_hsalsa20(salt16, key32):
    out = crypto_core_hsalsa20(
        in_=salt16,
        k=key32,
        c=salt16
    )
    assert isinstance(out, binary_type)
    assert len(out) == crypto_core_hsalsa20_OUTPUTBYTES

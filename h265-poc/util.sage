from Crypto.Cipher import AES
from binascii import unhexlify

zero_block = unhexlify('00'*16)
one_block  = unhexlify('11'*16)

_aes_ecb_cache = {}

def _get_aes_ecb(key):
    aes = _aes_ecb_cache.get(key)
    if aes is None:
        aes = AES.new(key, AES.MODE_ECB)
        _aes_ecb_cache[key] = aes
    return aes

_BIT_REV = bytes(int(f'{i:08b}'[::-1], 2) for i in range(256))

_F_from_int = None
_elem_to_int = None

def _resolve_field_api():
    global _F_from_int, _elem_to_int
    _F_from_int = getattr(F, 'from_integer', None) or F.fetch_int
    _z = F.zero()
    if hasattr(_z, 'to_integer'):
        _elem_to_int = lambda e: int(e.to_integer())
    else:
        _elem_to_int = lambda e: int(e.integer_representation())


def block_aes(block, key):
    assert(len(block) == 16)
    return _get_aes_ecb(key).encrypt(block)

def block_aes_inverse(block, key):
    assert(len(block) == 16)
    return _get_aes_ecb(key).decrypt(block)


def byte_array_to_field_element(block):
    assert(len(block) == 16)
    if _F_from_int is None:
        _resolve_field_api()
    int_val = int.from_bytes(block.translate(_BIT_REV), 'little')
    return _F_from_int(int_val)

def field_element_to_byte_array(element):
    if _elem_to_int is None:
        _resolve_field_api()
    int_val = _elem_to_int(element)
    return int_val.to_bytes(16, 'little').translate(_BIT_REV)


def byte_array_to_field_element_gcm_siv(block):
    assert(len(block) == 16)
    if _F_from_int is None:
        _resolve_field_api()
    return _F_from_int(int.from_bytes(block, 'little'))

def field_element_to_byte_array_gcm_siv(element):
    if _elem_to_int is None:
        _resolve_field_api()
    return _elem_to_int(element).to_bytes(16, 'little')


def byte_array_to_bitvector(byte_array):
    result = []
    for i in range(len(byte_array)):
        for j in range(8):
            result.append(byte_array[i] >> j & 0x1)
    return result

def xor_block(block_a, block_b):
    assert(len(block_a) == len(block_b))
    return bytes([a ^^ b for a, b in zip(block_a, block_b)])


def _gcm_keystream(key, nonce12, length):
    aes = _get_aes_ecb(key)
    n_blocks = (length + 15) // 16
    ctrs = b''.join(
        nonce12 + ((2 + i) & 0xFFFFFFFF).to_bytes(4, 'big')
        for i in range(n_blocks)
    )
    return aes.encrypt(ctrs)[:length]
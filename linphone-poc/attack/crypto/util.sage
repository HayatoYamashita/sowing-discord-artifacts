from Crypto.Cipher import AES
from binascii import unhexlify

zero_block = unhexlify('00'*16)
one_block = unhexlify('11'*16)

def block_aes(block, key):
    """Encrypt a single 16-byte block using AES-CBC with a zero IV."""
    assert(len(block) == 16)
    aes = AES.new(key, AES.MODE_CBC, iv=zero_block)
    return aes.encrypt(block)

def block_aes_inverse(block, key):
    """Decrypt a single 16-byte block using AES-CBC with a zero IV."""
    assert(len(block) == 16)
    aes = AES.new(key, AES.MODE_CBC, iv=zero_block)
    return aes.decrypt(block)

def byte_array_to_field_element(block):
    """Convert a 16-byte array to a GF(2^128) element (Standard GCM format)."""
    assert(len(block) == 16)
    field_element = 0
    for i in range(128):
        if (block[i // 8] >> (7 - (i % 8))) & 1 == 1:
            field_element += x^i
    return F(field_element)

def field_element_to_byte_array(element):
    """Convert a GF(2^128) element back to a 16-byte array (Standard GCM format)."""
    coeff = element.polynomial().coefficients(sparse=False)
    result = [0 for _ in range(16)]
    for i in range(len(coeff)):
        if coeff[i] == 1:
            result[i // 8] |= (1 << ((7 - i) % 8))
    return bytes(result)

def byte_array_to_field_element_gcm_siv(block):
    """Convert a 16-byte array to a GF(2^128) element (GCM-SIV format)."""
    assert(len(block) == 16)
    field_element = 0
    for i in range(128):
        if (block[i // 8] >> (i % 8)) & 1 == 1:
            field_element += x^i
    return F(field_element)

def field_element_to_byte_array_gcm_siv(element):
    """Convert a GF(2^128) element back to a 16-byte array (GCM-SIV format)."""
    coeff = element.polynomial().coefficients(sparse=False)
    result = [0 for _ in range(16)]
    for i in range(len(coeff)):
        if coeff[i] == 1:
            result[i // 8] |= (1 << (i % 8))
    return bytes(result)

def byte_array_to_bitvector(byte_array):
    """Convert a byte array to a list of bits (little-endian per byte)."""
    result = []
    for i in range(len(byte_array)):
        for j in range(8):
            result.append(byte_array[i] >> j & 0x1)
    return result

def xor_block(block_a, block_b):
    """XOR two byte arrays of equal length using SageMath operator."""
    assert(len(block_a) == len(block_b))
    return bytes([a ^^ b for a, b in zip(block_a, block_b)])
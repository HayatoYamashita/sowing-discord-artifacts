from Crypto.Cipher import AES

try:
    load('util.sage') 
except:
    pass

F = GF(2^128)
F2.<x> = GF(2)[]
p = x^128 + x^7 + x^2 + x + 1
F = GF(2^128, 'x', modulus=p)

def block_aes_encrypt(block_bytes, key_bytes):
    """Encrypt a single 16-byte block using AES-ECB."""
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(block_bytes)

def gcm_1block(key1, key2, 
               nonce1, nonce2,        
               ct_correction_index,   
               ct_len_bytes, ct_blocks,
               ad_len_bytes1, ad_blocks1,
               ad_len_bytes2, ad_blocks2):
    """
    Calculate the ciphertext correction block to forge a single valid tag 
    for two different AES-GCM keys by solving the GHASH polynomial equations.
    """
    zero_block = b'\x00' * 16
    H1 = byte_array_to_field_element(block_aes_encrypt(zero_block, key1))
    H2 = byte_array_to_field_element(block_aes_encrypt(zero_block, key2))
    
    j0_1 = nonce1 + b'\x00\x00\x00\x01' 
    j0_2 = nonce2 + b'\x00\x00\x00\x01'
    
    tag_mask1 = byte_array_to_field_element(block_aes_encrypt(j0_1, key1))
    tag_mask2 = byte_array_to_field_element(block_aes_encrypt(j0_2, key2))
    
    ad_len_bits1 = ad_len_bytes1 * 8
    ct_len_bits  = ct_len_bytes * 8 
    ad_len_bits2 = ad_len_bytes2 * 8
    
    len_block_bytes1 = int(ad_len_bits1).to_bytes(8, 'big') + int(ct_len_bits).to_bytes(8, 'big')
    len_block1 = byte_array_to_field_element(len_block_bytes1)

    len_block_bytes2 = int(ad_len_bits2).to_bytes(8, 'big') + int(ct_len_bits).to_bytes(8, 'big')
    len_block2 = byte_array_to_field_element(len_block_bytes2)

    A1 = [byte_array_to_field_element(block) for block in ad_blocks1]
    A2 = [byte_array_to_field_element(block) for block in ad_blocks2]
    C  = [byte_array_to_field_element(block) for block in ct_blocks]

    AC1 = A1 + C
    AC2 = A2 + C
    
    num_blocks1 = len(AC1)
    num_blocks2 = len(AC2)

    abs_idx1 = len(A1) + ct_correction_index
    abs_idx2 = len(A2) + ct_correction_index

    sum_h1 = sum([H1^(num_blocks1 + 1 - i) * AC1[i] for i in range(num_blocks1) if i != abs_idx1])
    sum_h2 = sum([H2^(num_blocks2 + 1 - i) * AC2[i] for i in range(num_blocks2) if i != abs_idx2])

    coeff1 = H1^(num_blocks1 - abs_idx1 + 1)
    coeff2 = H2^(num_blocks2 - abs_idx2 + 1)
    
    a = coeff1 + coeff2
    b = sum_h1 + sum_h2 + len_block1*H1 + tag_mask1 + len_block2*H2 + tag_mask2

    if a == 0:
        raise ValueError("Coefficients cancel out (a=0). Keys are likely identical.")
        
    X = b / a
    
    ct_blocks[ct_correction_index] = field_element_to_byte_array(X)
    
    AC1[abs_idx1] = X
    tag_result_h1 = sum([H1^(num_blocks1 + 1 - i) * AC1[i] for i in range(num_blocks1)]) + H1*len_block1 + tag_mask1
    tag_result_bytes = field_element_to_byte_array(tag_result_h1)

    return ad_blocks1, ad_blocks2, ct_blocks, tag_result_bytes
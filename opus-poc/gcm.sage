from Crypto.Cipher import AES
load('util.sage')

F = GF(2^128)
F2.<x> = GF(2)[]
p = x^128 + x^7 + x^2 + x + 1
F = GF(2^128, 'x', modulus=p)

def gcm_1block(key1, key2, nonce,
        correction_index,
        num_ct_blocks, ct_blocks,
        num_ad_blocks, ad_blocks):
    
    # Derive hash subkeys and tag masks for both keys
    H1 = byte_array_to_field_element(block_aes(zero_block, key1))
    H2 = byte_array_to_field_element(block_aes(zero_block, key2))
    tag_mask1 = byte_array_to_field_element(block_aes(nonce + unhexlify('00000001'), key1))
    tag_mask2 = byte_array_to_field_element(block_aes(nonce + unhexlify('00000001'), key2))
    
    ad_len_bits = num_ad_blocks * 128
    ct_len_bits = num_ct_blocks * 128
    len_block_bytes = long_to_bytes(ad_len_bits, 8) + long_to_bytes(ct_len_bits, 8)
    len_block = byte_array_to_field_element(len_block_bytes)

    # Convert block byte arrays to GF(2^128) field elements
    A = [byte_array_to_field_element(block) for block in ad_blocks]
    C = [byte_array_to_field_element(block) for block in ct_blocks]

    AC = A + C
    num_blocks = num_ad_blocks + num_ct_blocks

    sum_h1 = sum([H1^(num_blocks + 1 - i) * AC[i] for i in range(num_blocks) if i != correction_index])
    sum_h2 = sum([H2^(num_blocks + 1 - i) * AC[i] for i in range(num_blocks) if i != correction_index])

    a = H1^(num_blocks - correction_index + 1) + H2^(num_blocks - correction_index + 1)
    
    b = sum_h1 + sum_h2 + len_block*H1 + tag_mask1 + len_block*H2 + tag_mask2

    # Solve linear equation to find the correction block X
    X = b / a
    
    AC[correction_index] = X

    # Compute the final valid authentication tag
    tag_result_h1 = sum([H1^(num_blocks + 1 - i) * AC[i] for i in range(num_blocks)]) + H1*len_block + tag_mask1
    
    tag_result_bytes = field_element_to_byte_array(tag_result_h1)

    for i in range(num_blocks):
        if i < num_ad_blocks:
            ad_blocks[i] = field_element_to_byte_array(AC[i])
        else:
            ct_blocks[i - num_ad_blocks] = field_element_to_byte_array(AC[i])
            
    return ad_blocks, ct_blocks, tag_result_bytes
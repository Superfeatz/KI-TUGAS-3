# Data Encryption Standard (DES) 

def rotate_left(bits, n):
    rotated = bits[n:] + bits[:n]
    return rotated

def generate_keys(key_input):
    perm_1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
    perm_2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
    shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

    binary_key = ''.join(format(ord(ch), '08b') for ch in key_input)
    intermediate_key = [''] * 56
    final_key = [''] * 48

    for i in range(len(perm_1)):
        intermediate_key[i] = binary_key[perm_1[i] - 1]
    
    C = intermediate_key[:28]
    D = intermediate_key[28:]

    for i in range(16):
        C = rotate_left(C, shifts[i])
        D = rotate_left(D, shifts[i])
        concatenated = C + D
        
        for j in range(len(perm_2)):
            final_key[j] = concatenated[perm_2[j] - 1]
        
        keys[i] = ''.join(final_key)

def initial_permutation(block):
    ip = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
    permuted_block = [''] * 64
    for i in range(len(ip)):
        permuted_block[i] = block[ip[i] - 1]
    return ''.join(permuted_block)

def final_permutation(block):
    fp = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
    permuted_block = [''] * 64
    for i in range(len(fp)):
        permuted_block[i] = block[fp[i] - 1]
    return ''.join(permuted_block)

def substitution_box(input_bits):
    s_boxes = [
        [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7], [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8], [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0], [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
        [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10], [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5], [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15], [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
        [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8], [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1], [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7], [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
        [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15], [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9], [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4], [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
        [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9], [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6], [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14], [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
        [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11], [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8], [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6], [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
        [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1], [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6], [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2], [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
        [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7], [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2], [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8], [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
    ]

    output_bits = ''
    for i in range(0, len(input_bits), 6):
        chunk = input_bits[i:i+6]
        row = int(chunk[0] + chunk[5], 2)
        col = int(chunk[1:5], 2)
        s_box = s_boxes[i // 6]  # Pilih S-box yang benar sesuai blok
        s_val = s_box[row][col]
        output_bits += format(s_val, '04b')

    return output_bits

def feistel_round(data, round_num):
    expansion = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
    perm = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]

    expanded_data = ''.join([data[expansion[i] - 1] for i in range(48)])
    xored_data = ''.join([str(int(expanded_data[j]) ^ int(keys[round_num][j])) for j in range(48)])
    
    substituted = substitution_box(xored_data)
    
    final_perm = ''.join([substituted[perm[i] - 1] for i in range(32)])
    
    return final_perm

def des_encrypt_block(block):
    binary_block = ''.join(format(ord(ch), '08b') for ch in block)
    permuted_block = initial_permutation(binary_block)
    left, right = permuted_block[:32], permuted_block[32:]
    
    for i in range(16):
        temp_right = right
        right = feistel_round(right, i)
        right = ''.join([str(int(left[j]) ^ int(right[j])) for j in range(32)])
        left = temp_right
    
    final_block = final_permutation(right + left)
    return final_block

def des_decrypt(ciphertext_bin):
    permuted_block = initial_permutation(ciphertext_bin)
    left, right = permuted_block[:32], permuted_block[32:]

    for i in range(15, -1, -1):
        temp_right = right
        right = feistel_round(right, i)
        right = ''.join([str(int(left[j]) ^ int(right[j])) for j in range(32)])
        left = temp_right

    final_block = final_permutation(right + left)
    
    # Convert binary back to ASCII text
    decrypted_text = ''
    for i in range(0, len(final_block), 8):
        decrypted_text += chr(int(final_block[i:i+8], 2))  # Convert binary to character
    
    return decrypted_text

def hex_to_bin(hex_str):
    return ''.join(format(int(hex_str[i:i+2], 16), '08b') for i in range(0, len(hex_str), 2))

def bin_to_hex(bin_str):
    return ''.join(format(int(bin_str[i:i+8], 2), '02x') for i in range(0, len(bin_str), 8))

# Main Program
keys = [''] * 16
# print("Select option: \n1. Encrypt\n2. Decrypt")
# user_choice = input("Enter choice (1/2): ")

# if user_choice == '1':
#     plaintext = input("Enter plaintext: ")
#     key = input("Enter character key: ")
    
#     generate_keys(key)
    
#     while len(plaintext) % 8 != 0:
#         plaintext += ' '
    
#     encrypted_result = ''
#     for i in range(0, len(plaintext), 8):
#         block = plaintext[i:i+8]
#         encrypted_result += des_encrypt_block(block)
    
#     print("Encrypted (hex):", bin_to_hex(encrypted_result))

# elif user_choice == '2':
#     ciphertext_hex = input("Enter ciphertext (hex): ")
#     key = input("Enter character key: ")
    
#     generate_keys(key)
    
#     ciphertext_bin = hex_to_bin(ciphertext_hex)
#     decrypted_result = ''
    
#     for i in range(0, len(ciphertext_bin), 64):
#         block = ciphertext_bin[i:i+64]
#         decrypted_result += des_decrypt(block)
    
#     print("Decrypted text:", decrypted_result.strip())  # Strip to remove padding spaces
# else:
#     print("Invalid choice.")

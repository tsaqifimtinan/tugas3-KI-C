"""
DES Core Implementation
-----------------------
Contains all DES encryption/decryption functions
"""
import random

# Initial Permutation Table
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

# Expansion D-box Table
exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutation Table
per = [16, 7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2, 8, 24, 14,
       32, 27, 3, 9,
       19, 13, 30, 6,
       22, 11, 4, 25]

# S-box Table
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final Permutation Table
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

def hex2bin(s):
    """Convert hexadecimal to binary"""
    mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
          '4': "0100", '5': "0101", '6': "0110", '7': "0111",
          '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
          'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    bin_str = ""
    for i in range(len(s)):
        bin_str += mp[s[i]]
    return bin_str

def bin2hex(s):
    """Convert binary to hexadecimal"""
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
          "0100": '4', "0101": '5', "0110": '6', "0111": '7',
          "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
          "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    hex_str = ""
    # Pad to multiple of 4 if needed
    while len(s) % 4 != 0:
        s = '0' + s
    for i in range(0, len(s), 4):
        ch = s[i:i+4]
        hex_str += mp[ch]
    return hex_str

def bin2dec(binary):
    """Convert binary to decimal"""
    decimal, i = 0, 0
    while binary != 0:
        dec = binary % 10
        decimal += dec * pow(2, i)
        binary = binary // 10
        i += 1
    return decimal

def dec2bin(num):
    """Convert decimal to binary"""
    res = bin(num).replace("0b", "")
    if len(res) % 4 != 0:
        div = len(res) // 4
        div += 1
        counter = (div * 4) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res

def permute(k, arr, n):
    """Permute the input using the table"""
    permutation = ""
    for i in range(0, n):
        permutation += k[arr[i] - 1]
    return permutation

def shift_left(k, nth_shifts):
    """Circular left shift by n bits"""
    for i in range(nth_shifts):
        k = k[1:] + k[0]
    return k

def xor(a, b):
    """XOR two binary strings"""
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans += "0"
        else:
            ans += "1"
    return ans

def generate_round_keys(key):
    """Generate 16 round keys from the main key"""
    # Key Permutation Table for PC-1
    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    # Key Permutation Table for PC-2 (48 bits selected from 56)
    # Permuted Choice 2 (PC-2) - reduces 56 to 48 bits
    key_comp = [14, 17, 11, 24, 1, 5, 3, 28,
                15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 47, 55, 30, 40, 51, 45,
                33, 48, 44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32, 22, 43]

    # Number of shifts for each round
    shift_table = [1, 1, 2, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1]

    # Convert key to binary
    key = hex2bin(key)

    # PC-1 Permutation
    key = permute(key, keyp, 56)

    # Split into left and right
    left = key[0:28]
    right = key[28:56]

    rkb = []  # Round keys in binary
    rk = []   # Round keys in hexadecimal
    for i in range(0, 16):
        # Shift left and right
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])

        # Combine
        combine_str = left + right
        
        # Debug: Check lengths
        if len(combine_str) != 56:
            print(f"ERROR at round {i}: combine_str length = {len(combine_str)}, should be 56")
            print(f"left length = {len(left)}, right length = {len(right)}")
            raise ValueError(f"Combined string has wrong length: {len(combine_str)}")

        # PC-2 Permutation
        round_key = permute(combine_str, key_comp, 48)

        rkb.append(round_key)
        rk.append(bin2hex(round_key))

    return rkb

def encrypt_decrypt(pt, rkb):
    """Main DES encryption/decryption function"""
    pt = hex2bin(pt)

    # Initial Permutation
    pt = permute(pt, initial_perm, 64)

    # Split into left and right
    left = pt[0:32]
    right = pt[32:64]

    for i in range(0, 16):
        # Expansion D-box
        right_expanded = permute(right, exp_d, 48)

        # XOR with round key
        x = xor(rkb[i], right_expanded)

        # S-boxes
        op = ""
        for j in range(0, 8):
            # Get 6-bit chunk
            chunk = x[j * 6:(j * 6) + 6]
            
            # Ensure chunk is exactly 6 bits
            if len(chunk) < 6:
                chunk = chunk.ljust(6, '0')
            
            # Row (first and last bit)
            row = int(chunk[0] + chunk[5], 2)
            
            # Column (middle 4 bits)
            col = int(chunk[1:5], 2)
            
            # Bounds check
            if row > 3 or col > 15:
                raise ValueError(f"S-box index out of range: row={row}, col={col}, chunk={chunk}")
            
            # S-box lookup
            val = sbox[j][row][col]
            op += dec2bin(val)

        # Permutation P
        op = permute(op, per, 32)

        # XOR with left
        x = xor(op, left)

        # Swap
        left = x
        if i != 15:
            left, right = right, left

    # Combination
    combine = left + right

    # Final permutation
    cipher_text = permute(combine, final_perm, 64)
    return cipher_text

def text_to_hex_blocks(text):
    """Convert text to 64-bit hex blocks"""
    # Convert to hex
    hex_str = text.encode('utf-8').hex().upper()
    
    # Pad to multiple of 16 (64 bits)
    while len(hex_str) % 16 != 0:
        hex_str += '0'
    
    # Split into 16-character blocks
    blocks = []
    for i in range(0, len(hex_str), 16):
        blocks.append(hex_str[i:i+16])
    
    return blocks

def hex_blocks_to_text(blocks, original_length):
    """Convert hex blocks back to text"""
    hex_str = ''.join(blocks)
    
    # Convert hex to bytes
    byte_data = bytes.fromhex(hex_str)
    
    # Decode and remove padding
    text = byte_data.decode('utf-8', errors='ignore')
    return text[:original_length]

def generate_random_key():
    """Generate a random 64-bit DES key (16 hex characters)"""
    hex_chars = '0123456789ABCDEF'
    key = ''.join(random.choice(hex_chars) for _ in range(16))
    return key

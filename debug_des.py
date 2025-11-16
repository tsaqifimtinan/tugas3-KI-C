"""
Debug DES Core Functions
"""
from des_core import *

# Test the exact error case
print("Testing key generation...")
key = '6A6C44863DB0A194'
print(f"Key: {key}")
print(f"Key length: {len(key)}")

try:
    rkb = generate_round_keys(key)
    print(f"SUCCESS! Round keys generated: {len(rkb)}")
except Exception as e:
    import traceback
    print(f"ERROR: Error generating round keys: {e}")
    traceback.print_exc()

print("\n" + "="*50 + "\n")

# Test 1: Simple text without emoji
print("Test 1: Simple ASCII text")
text1 = "Hello Bob"
print(f"Input: {text1}")
try:
    hex_blocks = text_to_hex_blocks(text1)
    print(f"Hex blocks: {hex_blocks}")
    
    key = generate_random_key()
    print(f"Key: {key}")
    
    rkb = generate_round_keys(key)
    print(f"Round keys generated: {len(rkb)}")
    
    encrypted_blocks = []
    for block in hex_blocks:
        print(f"Encrypting block: {block}")
        cipher_block = bin2hex(encrypt_decrypt(block, rkb))
        encrypted_blocks.append(cipher_block)
        print(f"Encrypted: {cipher_block}")
    
    print("✅ Test 1 passed!")
except Exception as e:
    import traceback
    print(f"❌ Test 1 failed: {e}")
    traceback.print_exc()

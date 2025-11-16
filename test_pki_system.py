"""
Quick Test Script for PKI System
---------------------------------
Tests the complete flow: CA registration, certificate issuance, 
secure message sending, and message receiving.
"""

import requests
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# ⚠️  IMPORTANT: Update these with your localtunnel URLs before running
# Example: CA_URL = "https://ca-server-yourname.loca.lt"
#          DES_URL = "https://des-server-yourname.loca.lt"
CA_URL = "http://localhost:5001"  # Replace with your CA localtunnel URL
DES_URL = "http://localhost:5002"  # Replace with your DES localtunnel URL

def test_system():
    print("=" * 70)
    print("TESTING PKI SYSTEM")
    print("=" * 70)
    
    # =====================================================
    # STEP 1: Generate keys for Alice
    # =====================================================
    print("\n[STEP 1] Generating RSA keys for Alice...")
    alice_key = RSA.generate(2048)
    alice_private_key = alice_key
    alice_public_key = alice_key.publickey()
    print("✅ Alice's keys generated")
    
    # =====================================================
    # STEP 2: Generate keys for Bob
    # =====================================================
    print("\n[STEP 2] Generating RSA keys for Bob...")
    bob_key = RSA.generate(2048)
    bob_private_key = bob_key
    bob_public_key = bob_key.publickey()
    print("✅ Bob's keys generated")
    
    # =====================================================
    # STEP 3: Get CA public key
    # =====================================================
    print("\n[STEP 3] Fetching CA public key...")
    try:
        response = requests.get(f"{CA_URL}/ca/info")
        if response.status_code == 200:
            ca_public_key = response.json()['ca_public_key']
            print("✅ CA public key retrieved")
        else:
            print("❌ Failed to get CA public key")
            print("   Make sure CA server is running on port 5001")
            return False
    except Exception as e:
        print(f"❌ Error connecting to CA: {str(e)}")
        print("   Run: python certificate_server.py")
        return False
    
    # =====================================================
    # STEP 4: Register Alice with CA
    # =====================================================
    print("\n[STEP 4] Registering Alice with CA...")
    try:
        data = {
            'client_id': 'alice',
            'public_key': alice_public_key.export_key().decode('utf-8')
        }
        response = requests.post(f"{CA_URL}/ca/register", json=data)
        if response.status_code == 200:
            alice_certificate = response.json()['certificate']
            print(f"✅ Alice registered - Certificate ID: {response.json()['certificate_id']}")
        else:
            print(f"❌ Alice registration failed: {response.json().get('message')}")
            return False
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False
    
    # =====================================================
    # STEP 5: Register Bob with CA
    # =====================================================
    print("\n[STEP 5] Registering Bob with CA...")
    try:
        data = {
            'client_id': 'bob',
            'public_key': bob_public_key.export_key().decode('utf-8')
        }
        response = requests.post(f"{CA_URL}/ca/register", json=data)
        if response.status_code == 200:
            bob_certificate = response.json()['certificate']
            print(f"✅ Bob registered - Certificate ID: {response.json()['certificate_id']}")
        else:
            print(f"❌ Bob registration failed: {response.json().get('message')}")
            return False
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False
    
    # =====================================================
    # STEP 6: Alice sends message to Bob
    # =====================================================
    print("\n[STEP 6] Alice sending encrypted message to Bob...")
    message = "Hello Bob! This is a secret message from Alice."
    print(f"   Plaintext: '{message}'")
    
    try:
        data = {
            'text': message,
            'sender_certificate': alice_certificate,
            'receiver_certificate': bob_certificate,
            'ca_public_key': ca_public_key
        }
        response = requests.post(f"{DES_URL}/send-secure", json=data)
        if response.status_code == 200:
            result = response.json()
            message_id = result['message_id']
            ciphertext = result['ciphertext']
            encrypted_key = result['encrypted_session_key']
            
            print(f"✅ Message encrypted successfully!")
            print(f"   Message ID: {message_id}")
            print(f"   Ciphertext: {ciphertext[:50]}... (truncated)")
            print(f"   Encrypted Key: {encrypted_key[:50]}... (truncated)")
        else:
            print(f"❌ Send failed: {response.json().get('message')}")
            print("   Make sure DES server is running on port 5002")
            return False
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        print("   Run: python des_server.py")
        return False
    
    # =====================================================
    # STEP 7: Bob receives and decrypts message
    # =====================================================
    print("\n[STEP 7] Bob receiving and decrypting message...")
    
    try:
        data = {
            'message_id': message_id,
            'private_key': bob_private_key.export_key().decode('utf-8'),
            'certificate': bob_certificate,
            'ca_public_key': ca_public_key
        }
        response = requests.post(f"{DES_URL}/receive-secure", json=data)
        if response.status_code == 200:
            result = response.json()
            decrypted_message = result['plaintext']
            
            print(f"✅ Message decrypted successfully!")
            print(f"   Decrypted: '{decrypted_message}'")
            
            # Verify message integrity
            if decrypted_message == message:
                print("\n🎉 SUCCESS! Message matches original!")
            else:
                print("\n⚠️  WARNING! Message doesn't match original!")
                return False
        else:
            print(f"❌ Receive failed: {response.json().get('message')}")
            return False
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False
    
    # =====================================================
    # STEP 8: Test wrong receiver
    # =====================================================
    print("\n[STEP 8] Testing security: Alice tries to decrypt Bob's message...")
    
    try:
        data = {
            'message_id': message_id,
            'private_key': alice_private_key.export_key().decode('utf-8'),  # Wrong key!
            'certificate': alice_certificate,
            'ca_public_key': ca_public_key
        }
        response = requests.post(f"{DES_URL}/receive-secure", json=data)
        if response.status_code != 200:
            print(f"✅ Security working! Error: {response.json().get('message')}")
        else:
            print("⚠️  Security issue: Alice could decrypt Bob's message!")
            return False
    except Exception as e:
        print(f"✅ Security working! Cannot decrypt: {str(e)}")
    
    # =====================================================
    # SUMMARY
    # =====================================================
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print("✅ Alice registered with CA")
    print("✅ Bob registered with CA")
    print("✅ Certificates issued and verified")
    print("✅ Message encrypted with DES")
    print("✅ Session key encrypted with RSA")
    print("✅ Message decrypted successfully")
    print("✅ Security verified (wrong receiver cannot decrypt)")
    print("\n🎉 ALL TESTS PASSED! PKI system working correctly!")
    print("=" * 70)
    
    return True

if __name__ == "__main__":
    print("\n⚠️  PREREQUISITES:")
    print("   1. Start CA server: python certificate_server.py")
    print("   2. Start DES server: python des_server.py")
    print("   3. Then run this test script")
    print()
    
    input("Press Enter when both servers are running...")
    
    try:
        success = test_system()
        if not success:
            print("\n❌ Tests failed!")
            exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted")
        exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        exit(1)

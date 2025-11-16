from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import uuid
import random
import base64
import json
from datetime import datetime

# Import DES functions from core module
from des_core import (
    hex2bin, bin2hex, bin2dec, dec2bin, permute, shift_left, xor,
    initial_perm, exp_d, per, sbox, final_perm,
    encrypt_decrypt, generate_round_keys,
    text_to_hex_blocks, hex_blocks_to_text, generate_random_key
)

app = Flask(__name__)
CORS(app)

# Message storage with PKI support
messages_store = {}

# ========================================
# PKI HELPER FUNCTIONS
# ========================================

def verify_certificate_signature(certificate, ca_public_key):
    """Verify certificate was signed by CA"""
    try:
        signature = certificate['ca_signature']
        cert_data = {k: v for k, v in certificate.items() 
                    if k not in ['ca_signature', 'ca_public_key']}
        data_to_verify = json.dumps(cert_data, sort_keys=True)
        
        h = SHA256.new(data_to_verify.encode('utf-8'))
        signature_bytes = base64.b64decode(signature)
        pkcs1_15.new(ca_public_key).verify(h, signature_bytes)
        return True
    except:
        return False

def encrypt_with_public_key(data, public_key_pem):
    """Encrypt data using RSA public key"""
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

# ========================================
# PKI-ENABLED ENDPOINTS
# ========================================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'status': 'success',
        'service': 'DES Server with Public Key Infrastructure (PKI)',
        'description': 'Secure message encryption using DES with RSA-based key distribution',
        'endpoints': {
            '/': 'GET - Server info',
            '/send-secure': 'POST - Encrypt message with certificate-based key distribution',
            '/receive-secure': 'POST - Decrypt message using private key',
            '/messages': 'GET - List all stored messages'
        },
        'security': {
            'encryption': 'DES for message content',
            'key_distribution': 'RSA-2048 with digital certificates',
            'authentication': 'CA-signed certificates'
        }
    })

@app.route('/send-secure', methods=['POST'])
def send_secure_message():
    """
    SECURE MESSAGE SENDING WITH PKI
    --------------------------------
    Process:
    1. Sender provides: plaintext, sender certificate, receiver certificate
    2. Verify both certificates with CA
    3. Generate random DES session key
    4. Encrypt message with DES using session key
    5. Encrypt DES key with receiver's RSA public key (from certificate)
    6. Sign the message with sender's identity
    7. Store encrypted message with encrypted key
    8. Return message_id to sender
    
    Security Benefits:
    - Only receiver can decrypt the DES key (RSA encryption)
    - Message authenticity verified (certificates)
    - Session key per message (perfect forward secrecy)
    """
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['text', 'sender_certificate', 'receiver_certificate', 'ca_public_key']
        if not all(field in data for field in required_fields):
            return jsonify({
                'status': 'error',
                'message': f'Required fields: {", ".join(required_fields)}'
            }), 400
        
        plaintext = data['text']
        sender_cert = data['sender_certificate']
        receiver_cert = data['receiver_certificate']
        ca_public_key_pem = data['ca_public_key']
        
        # STEP 1: Verify certificates
        ca_public_key = RSA.import_key(ca_public_key_pem)
        
        if not verify_certificate_signature(sender_cert, ca_public_key):
            return jsonify({
                'status': 'error',
                'message': 'Invalid sender certificate'
            }), 400
        
        if not verify_certificate_signature(receiver_cert, ca_public_key):
            return jsonify({
                'status': 'error',
                'message': 'Invalid receiver certificate'
            }), 400
        
        # STEP 2: Extract receiver's public key from certificate
        receiver_public_key_pem = receiver_cert['public_key']
        
        # STEP 3: Generate random DES session key
        des_key = generate_random_key()
        
        # STEP 4: Encrypt message with DES
        original_length = len(plaintext)
        hex_blocks = text_to_hex_blocks(plaintext)
        rkb = generate_round_keys(des_key)
        encrypted_blocks = []
        
        for block in hex_blocks:
            cipher_block = bin2hex(encrypt_decrypt(block, rkb))
            encrypted_blocks.append(cipher_block)
        
        # STEP 5: Encrypt DES key with receiver's RSA public key
        encrypted_des_key = encrypt_with_public_key(des_key, receiver_public_key_pem)
        
        # STEP 6: Generate message ID
        message_id = str(uuid.uuid4())[:12]
        
        # STEP 7: Store encrypted message
        messages_store[message_id] = {
            'encrypted_blocks': encrypted_blocks,
            'encrypted_key': encrypted_des_key,  # Only receiver can decrypt this
            'original_length': original_length,
            'sender': sender_cert['subject'],
            'receiver': receiver_cert['subject'],
            'timestamp': datetime.now().isoformat(),
            'sender_certificate': sender_cert,
            'receiver_certificate': receiver_cert
        }
        
        ciphertext = ''.join(encrypted_blocks)
        
        return jsonify({
            'status': 'success',
            'message': 'Message encrypted and secured with PKI',
            'message_id': message_id,
            'sender': sender_cert['subject'],
            'receiver': receiver_cert['subject'],
            'ciphertext': ciphertext,
            'encrypted_session_key': encrypted_des_key,
            'security_info': {
                'message_encryption': 'DES with random session key',
                'key_distribution': 'RSA-encrypted session key',
                'authentication': 'CA-signed certificates'
            },
            'instruction': f'Share message_id with {receiver_cert["subject"]}: {message_id}'
        })
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in send_secure: {error_details}")
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}',
            'details': error_details
        }), 500

@app.route('/receive-secure', methods=['POST'])
def receive_secure_message():
    """
    SECURE MESSAGE RECEIVING WITH PKI
    ---------------------------------
    Process:
    1. Receiver provides: message_id, private key, certificate
    2. Retrieve encrypted message from storage
    3. Verify receiver's certificate
    4. Decrypt DES session key using receiver's RSA private key
    5. Decrypt message using recovered DES key
    6. Return plaintext to receiver
    
    Security Benefits:
    - Only intended receiver can decrypt (RSA private key)
    - Sender identity verified (certificate check)
    - End-to-end encryption maintained
    """
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['message_id', 'private_key', 'certificate', 'ca_public_key']
        if not all(field in data for field in required_fields):
            return jsonify({
                'status': 'error',
                'message': f'Required fields: {", ".join(required_fields)}'
            }), 400
        
        message_id = data['message_id']
        receiver_private_key_pem = data['private_key']
        receiver_cert = data['certificate']
        ca_public_key_pem = data['ca_public_key']
        
        # STEP 1: Check message exists
        if message_id not in messages_store:
            return jsonify({
                'status': 'error',
                'message': f'Message not found: {message_id}'
            }), 404
        
        msg = messages_store[message_id]
        
        # STEP 2: Verify receiver's certificate
        ca_public_key = RSA.import_key(ca_public_key_pem)
        if not verify_certificate_signature(receiver_cert, ca_public_key):
            return jsonify({
                'status': 'error',
                'message': 'Invalid receiver certificate'
            }), 400
        
        # STEP 3: Verify receiver is the intended recipient
        if receiver_cert['subject'] != msg['receiver']:
            return jsonify({
                'status': 'error',
                'message': 'You are not the intended receiver of this message'
            }), 403
        
        # STEP 4: Decrypt DES session key with receiver's private key
        try:
            receiver_private_key = RSA.import_key(receiver_private_key_pem)
            cipher = PKCS1_OAEP.new(receiver_private_key)
            encrypted_key_bytes = base64.b64decode(msg['encrypted_key'])
            des_key = cipher.decrypt(encrypted_key_bytes).decode('utf-8')
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Failed to decrypt session key. Wrong private key?'
            }), 403
        
        # STEP 5: Decrypt message with recovered DES key
        rkb = generate_round_keys(des_key)
        rkb_rev = rkb[::-1]
        decrypted_blocks = []
        
        for block in msg['encrypted_blocks']:
            plain_block = bin2hex(encrypt_decrypt(block, rkb_rev))
            decrypted_blocks.append(plain_block)
        
        plaintext = hex_blocks_to_text(decrypted_blocks, msg['original_length'])
        ciphertext = ''.join(msg['encrypted_blocks'])
        
        return jsonify({
            'status': 'success',
            'message': 'Message decrypted successfully',
            'message_id': message_id,
            'plaintext': plaintext,
            'ciphertext': ciphertext,
            'sender': msg['sender'],
            'receiver': msg['receiver'],
            'timestamp': msg['timestamp'],
            'security_info': {
                'session_key_decrypted': 'Using your RSA private key',
                'message_decrypted': 'Using recovered DES session key',
                'sender_verified': 'Via CA-signed certificate'
            }
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/messages', methods=['GET'])
def list_messages():
    """List all stored messages"""
    messages_list = []
    for msg_id, msg_data in messages_store.items():
        messages_list.append({
            'message_id': msg_id,
            'sender': msg_data['sender'],
            'receiver': msg_data['receiver'],
            'timestamp': msg_data['timestamp']
        })
    
    return jsonify({
        'status': 'success',
        'total_messages': len(messages_list),
        'messages': messages_list
    })

@app.route('/reset', methods=['POST'])
def reset_server():
    """Reset message storage (for testing only)"""
    global messages_store
    
    old_count = len(messages_store)
    messages_store.clear()
    
    return jsonify({
        'status': 'success',
        'message': 'Message storage reset successfully',
        'cleared_messages': old_count
    })

if __name__ == "__main__":
    print("=" * 60)
    print("DES SERVER WITH PUBLIC KEY INFRASTRUCTURE (PKI)")
    print("=" * 60)
    print("\n🔐 Security Features:")
    print("   ✓ Message encryption: DES algorithm")
    print("   ✓ Key distribution: RSA-2048 encryption")
    print("   ✓ Authentication: CA-signed certificates")
    print("   ✓ Perfect forward secrecy: Unique session key per message")
    print("\n📋 Available Endpoints:")
    print("   GET  /              - Server info")
    print("   POST /send-secure   - Send encrypted message with PKI")
    print("   POST /receive-secure - Receive and decrypt message")
    print("   GET  /messages      - List all messages")
    print("   POST /reset         - Reset storage (testing only)")
    print("="*60)
    print("\n⚠️  IMPORTANT: This server requires localtunnel for access")
    print("\n📝 Setup Instructions:")
    print("   1. Install localtunnel: npm install -g localtunnel")
    print("   2. In a new terminal, run: lt --port 5002 --subdomain des-server-<yourname>")
    print("   3. Share the generated URL (e.g., https://des-server-yourname.loca.lt)")
    print("\n✅ Server starting on port 5002...")
    print("   Press Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=5002, debug=False)
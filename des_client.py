"""
PKI-Enabled DES Client
----------------------
Secure messaging client using Public Key Infrastructure:
1. Register with CA to get digital certificate
2. Send encrypted messages using receiver's certificate
3. Receive messages using own private key
"""

import requests
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class PKIClient:
    def __init__(self, client_id, ca_url, des_server_url):
        self.client_id = client_id
        self.ca_url = ca_url
        self.des_server_url = des_server_url
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.ca_public_key = None
        
    def generate_keys(self):
        """Generate RSA key pair for this client"""
        print(f"\n🔐 Generating RSA key pair for {self.client_id}...")
        key = RSA.generate(2048)
        self.private_key = key
        self.public_key = key.publickey()
        print("✅ Keys generated successfully!")
        
    def register_with_ca(self):
        """Register with CA and get digital certificate"""
        if not self.public_key:
            self.generate_keys()
        
        print(f"\n📝 Registering with Certificate Authority...")
        
        # Get CA public key first
        response = requests.get(f"{self.ca_url}/ca/info")
        if response.status_code == 200:
            self.ca_public_key = response.json()['ca_public_key']
        else:
            print("❌ Failed to get CA public key")
            return False
        
        # Register and get certificate
        data = {
            'client_id': self.client_id,
            'public_key': self.public_key.export_key().decode('utf-8')
        }
        
        response = requests.post(f"{self.ca_url}/ca/register", json=data)
        
        if response.status_code == 200:
            result = response.json()
            self.certificate = result['certificate']
            print(f"✅ Certificate issued successfully!")
            print(f"   Certificate ID: {result['certificate_id']}")
            print(f"   Valid until: {self.certificate['expires_at']}")
            return True
        else:
            print(f"❌ Registration failed: {response.json().get('message', 'Unknown error')}")
            return False
    
    def get_receiver_certificate(self, receiver_id):
        """Get receiver's certificate from CA"""
        print(f"\n🔍 Fetching certificate for {receiver_id}...")
        
        response = requests.post(
            f"{self.ca_url}/ca/get-cert",
            json={'client_id': receiver_id}
        )
        
        if response.status_code == 200:
            cert = response.json()['certificate']
            print(f"✅ Certificate retrieved for {receiver_id}")
            return cert
        else:
            print(f"❌ Certificate not found for {receiver_id}")
            return None
    
    def send_secure_message(self, receiver_id, message):
        """Send encrypted message using PKI"""
        print(f"\n📤 Sending secure message to {receiver_id}...")
        
        # Get receiver's certificate
        receiver_cert = self.get_receiver_certificate(receiver_id)
        if not receiver_cert:
            return False, "Receiver certificate not found"
        
        # Prepare request
        data = {
            'text': message,
            'sender_certificate': self.certificate,
            'receiver_certificate': receiver_cert,
            'ca_public_key': self.ca_public_key
        }
        
        response = requests.post(
            f"{self.des_server_url}/send-secure",
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Message encrypted and sent successfully!")
            return True, result
        else:
            error_msg = response.json().get('message', 'Unknown error')
            print(f"❌ Failed: {error_msg}")
            return False, error_msg
    
    def receive_secure_message(self, message_id):
        """Receive and decrypt message using private key"""
        print(f"\n📥 Receiving secure message {message_id}...")
        
        data = {
            'message_id': message_id,
            'private_key': self.private_key.export_key().decode('utf-8'),
            'certificate': self.certificate,
            'ca_public_key': self.ca_public_key
        }
        
        response = requests.post(
            f"{self.des_server_url}/receive-secure",
            json=data
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Message decrypted successfully!")
            return True, result
        else:
            error_msg = response.json().get('message', 'Unknown error')
            print(f"❌ Failed: {error_msg}")
            return False, error_msg

def main():
    """Main client interface"""
    print("=" * 60)
    print("     PKI-ENABLED SECURE MESSAGING CLIENT")
    print("=" * 60)
    
    # Initialize client
    print("\n🔧 CLIENT SETUP")
    print("⚠️  Use localtunnel URLs (e.g., https://ca-server-yourname.loca.lt)\n")
    client_id = input("Enter your client ID: ").strip()
    ca_url = input("CA Server URL: ").strip()
    des_server_url = input("DES Server URL: ").strip()
    
    if not ca_url or not des_server_url:
        print("\n❌ Error: Server URLs are required!")
        return
    
    client = PKIClient(client_id, ca_url, des_server_url)
    
    # Register with CA
    if not client.register_with_ca():
        print("\n❌ Failed to register with CA. Exiting...")
        return
    
    # Main menu
    while True:
        print("\n" + "=" * 60)
        print("MENU:")
        print("  1. Send Secure Message")
        print("  2. Receive Secure Message")
        print("  3. View My Certificate")
        print("  4. Exit")
        print("=" * 60)
        
        choice = input("\nChoose option (1/2/3/4): ").strip()
        
        if choice == '1':
            # SEND MESSAGE
            print("\n=== SEND SECURE MESSAGE ===")
            receiver_id = input("Receiver's Client ID: ").strip()
            message = input("Your message: ").strip()
            
            success, result = client.send_secure_message(receiver_id, message)
            
            if success:
                print(f"\n✅ SUCCESS!")
                print(f"Message ID: {result['message_id']}")
                print(f"Receiver: {result['receiver']}")
                print(f"\n🔐 Security Info:")
                print(f"   - Message encrypted with DES")
                print(f"   - Session key encrypted with receiver's RSA public key")
                print(f"   - Your identity verified via CA certificate")
                print(f"\nShare this Message ID with {receiver_id}: {result['message_id']}")
        
        elif choice == '2':
            # RECEIVE MESSAGE
            print("\n=== RECEIVE SECURE MESSAGE ===")
            message_id = input("Message ID: ").strip()
            
            success, result = client.receive_secure_message(message_id)
            
            if success:
                print(f"\n✅ SUCCESS!")
                print(f"From: {result['sender']}")
                print(f"Message: {result['plaintext']}")
                print(f"Sent: {result['timestamp']}")
                print(f"\n🔐 Security Info:")
                print(f"   - Session key decrypted with your RSA private key")
                print(f"   - Message decrypted with recovered DES key")
                print(f"   - Sender verified via CA certificate")
        
        elif choice == '3':
            # VIEW CERTIFICATE
            print("\n=== YOUR CERTIFICATE ===")
            if client.certificate:
                print(f"Certificate ID: {client.certificate['certificate_id']}")
                print(f"Subject: {client.certificate['subject']}")
                print(f"Issued: {client.certificate['issued_at']}")
                print(f"Expires: {client.certificate['expires_at']}")
                print(f"Issuer: {client.certificate['issuer']}")
            else:
                print("No certificate available")
        
        elif choice == '4':
            print("\n👋 Goodbye!")
            break
        else:
            print("\n❌ Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Program interrupted. Goodbye!")
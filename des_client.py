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
import os
import base64
import random

class PKIClient:
    def __init__(self, client_id, ca_url, des_server_url):
        self.client_id = client_id
        self.ca_url = ca_url
        self.des_server_url = des_server_url
        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.ca_public_key = None
        self.cert_file = f"{client_id}_certificate.json"
        
    def save_cert(self):
        """Save certificate to file"""
        try:
            # Save certificate
            with open(self.cert_file, 'w') as f:
                json.dump(self.certificate, f, indent=2)
            
            print(f"💾 Certificate saved to: {self.cert_file}")
        except Exception as e:
            print(f"⚠️  Warning: Could not save certificate: {e}")
    
    def load_cert(self):
        """Load existing certificate from file"""
        try:
            if os.path.exists(self.cert_file):
                # Load certificate
                with open(self.cert_file, 'r') as f:
                    self.certificate = json.load(f)
                
                # Extract keys from certificate
                self.public_key = self.certificate.get('public_key', '')
                self.private_key = self.certificate.get('private_key', '')
                
                print(f"✅ Loaded existing certificate from disk")
                print(f"   Subject: {self.certificate['subject']}")
                print(f"   Certificate ID: {self.certificate['certificate_id']}")
                return True
        except Exception as e:
            print(f"⚠️  Could not load existing certificate: {e}")
        
        return False
        
    def generate_keys(self):
        """Generate simple key pair (base64 encoded random strings)"""
        print(f"\n🔐 Generating NEW key pair for {self.client_id}...")
        # Generate random keys (simplified - just random strings)
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        self.private_key = base64.b64encode(random_bytes).decode('utf-8')
        self.public_key = base64.b64encode(random_bytes[:16]).decode('utf-8')
        print("✅ Keys generated successfully!")
        
    def register_with_ca(self, force_new=False):
        """Register with CA and get digital certificate"""
        
        # Try to load existing certificate first (unless forced to create new)
        if not force_new and self.load_cert():
            # Get CA public key
            response = requests.get(f"{self.ca_url}/ca/info")
            if response.status_code == 200:
                self.ca_public_key = response.json()['ca_public_key']
                print("✅ Using existing registration")
                return True
        
        # Generate new keys if needed
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
            'public_key': self.public_key
        }
        
        response = requests.post(f"{self.ca_url}/ca/register", json=data)
        
        if response.status_code == 200:
            result = response.json()
            self.certificate = result['certificate']
            # Store private key in certificate for later use
            self.certificate['private_key'] = self.private_key
            print(f"✅ Certificate issued successfully!")
            print(f"   Certificate ID: {result['certificate_id']}")
            print(f"   Valid until: {self.certificate['expires_at']}")
            
            # Save to disk for future use
            self.save_cert()
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
            'private_key': self.private_key,
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
        print("  4. Re-register (Generate New Keys)")
        print("  5. Exit")
        print("=" * 60)
        
        choice = input("\nChoose option (1/2/3/4/5): ").strip()
        
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
                print(f"   - Session key encoded with base64")
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
                print(f"   - Session key decoded with base64")
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
            # RE-REGISTER (Generate new keys)
            print("\n⚠️  WARNING: This will generate NEW keys and invalidate old messages!")
            confirm = input("Are you sure? (yes/no): ").strip().lower()
            if confirm == 'yes':
                if client.register_with_ca(force_new=True):
                    print("✅ Re-registered successfully with new keys!")
                else:
                    print("❌ Re-registration failed!")
        
        elif choice == '5':
            print("\n👋 Goodbye!")
            break
        else:
            print("\n❌ Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Program interrupted. Goodbye!")
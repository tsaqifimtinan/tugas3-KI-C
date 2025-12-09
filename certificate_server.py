"""
Certificate Authority (CA) Server
----------------------------------
Implements Public Key Infrastructure (PKI) for secure key distribution:
- Issues digital certificates to clients
- Signs certificates with CA's private key (simulated)
- Verifies certificate authenticity
- Maintains certificate registry

NOTE: This is a simplified implementation without external crypto libraries
For production use, proper RSA/cryptography libraries are required.
"""

import json
import random
import hashlib
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


# ========================================
# CA KEY PAIR GENERATION (SIMULATED)
# ========================================
# In a real implementation, use proper RSA libraries
# This is a simplified simulation for educational purposes

print("Generating Certificate Authority (CA) key pair...")

ca_private_key = hashlib.sha256(b"CA_PRIVATE_KEY_SEED" + str(time.time()).encode()).hexdigest()
ca_public_key = hashlib.sha256(ca_private_key.encode()).hexdigest()
print("✅ CA keys generated successfully!")

# Certificate storage: {cert_id: certificate_data}
certificates_db = {}
# Client public keys: {client_id: public_key_pem}
client_keys_db = {}

# ========================================
# HELPER FUNCTIONS
# ========================================

def generate_id():
    """Generate a unique ID"""
    return hashlib.sha256(str(time.time()).encode() + str(random.random()).encode()).hexdigest()[:12]

def get_timestamp():
    """Get current timestamp"""
    return time.strftime('%Y-%m-%dT%H:%M:%S')

def add_days(timestamp_str, days):
    """Add days to a timestamp"""
    t = time.mktime(time.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S'))
    t += days * 24 * 60 * 60
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(t))

def sign_data(data, private_key):
    """Sign data with private key using SHA256"""
    combined = data + private_key
    signature = hashlib.sha256(combined.encode()).hexdigest()
    return signature

def verify_signature(data, signature, public_key):
    """Verify signature with public key"""
    try:
        expected_sig = hashlib.sha256((data + ca_private_key).encode()).hexdigest()
        return signature == expected_sig
    except:
        return False

def create_certificate(client_id, client_public_key_pem, validity_days=365):
    """
    Create a digital certificate for a client
    
    Certificate contains:
    - Certificate ID
    - Client ID (subject)
    - Client's public key
    - Validity period
    - CA's digital signature
    """
    cert_id = generate_id()
    issued_at = get_timestamp()
    expires_at = add_days(issued_at, validity_days)
    
    # Certificate data to be signed
    cert_data = {
        'certificate_id': cert_id,
        'subject': client_id,
        'public_key': client_public_key_pem,
        'issued_at': issued_at,
        'expires_at': expires_at,
        'issuer': 'Trusted Certificate Authority'
    }
    
    # Create signature over certificate data
    data_to_sign = json.dumps(cert_data, sort_keys=True)
    signature = sign_data(data_to_sign, ca_private_key)
    
    # Complete certificate with signature
    certificate = {
        **cert_data,
        'ca_signature': signature,
        'ca_public_key': ca_public_key
    }
    
    return cert_id, certificate


# ========================================
# HTTP SERVER HANDLER
# ========================================

class CAHandler(BaseHTTPRequestHandler):
    """Handle HTTP requests for CA server"""
    
    def _send_json_response(self, status_code, data):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_OPTIONS(self):
        """Handle preflight CORS requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        path = urlparse(self.path).path
        
        if path == '/':
            self._send_json_response(200, {
                'status': 'success',
                'service': 'Certificate Authority (CA) Server',
                'description': 'Issues and verifies digital certificates for secure key distribution',
                'endpoints': {
                    '/ca/info': 'GET - Get CA public key',
                    '/ca/register': 'POST - Register client and get certificate',
                    '/ca/verify': 'POST - Verify certificate authenticity',
                    '/ca/get-cert': 'POST - Get certificate by client_id',
                    '/ca/certificates': 'GET - List all certificates'
                },
                'total_certificates': len(certificates_db)
            })
        
        elif path == '/ca/info':
            self._send_json_response(200, {
                'status': 'success',
                'ca_public_key': ca_public_key,
                'algorithm': 'SHA256 signatures (simplified)'
            })
        
        elif path == '/ca/certificates':
            certs_list = []
            for cert_id, cert in certificates_db.items():
                certs_list.append({
                    'certificate_id': cert_id,
                    'subject': cert['subject'],
                    'issued_at': cert['issued_at'],
                    'expires_at': cert['expires_at']
                })
            
            self._send_json_response(200, {
                'status': 'success',
                'total_certificates': len(certs_list),
                'certificates': certs_list
            })
        
        else:
            self._send_json_response(404, {
                'status': 'error',
                'message': 'Not found'
            })
    
    def do_POST(self):
        """Handle POST requests"""
        path = urlparse(self.path).path
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(body) if body else {}
        except:
            self._send_json_response(400, {
                'status': 'error',
                'message': 'Invalid JSON'
            })
            return
        
        if path == '/ca/register':
            self._handle_register(data)
        elif path == '/ca/verify':
            self._handle_verify(data)
        elif path == '/ca/get-cert':
            self._handle_get_cert(data)
        elif path == '/ca/reset':
            self._handle_reset()
        else:
            self._send_json_response(404, {
                'status': 'error',
                'message': 'Not found'
            })
    
    def _handle_register(self, data):
        """Handle client registration"""
        if not data or 'client_id' not in data or 'public_key' not in data:
            self._send_json_response(400, {
                'status': 'error',
                'message': 'Required: client_id, public_key'
            })
            return
        
        client_id = data['client_id']
        client_public_key_pem = data['public_key']
        
        # Check if client already registered
        if client_id in client_keys_db:
            for cert_id, cert in certificates_db.items():
                if cert['subject'] == client_id:
                    self._send_json_response(200, {
                        'status': 'success',
                        'message': 'Client already registered, returning existing certificate',
                        'certificate_id': cert_id,
                        'certificate': cert,
                        'reused': True
                    })
                    return
        
        # Create certificate
        cert_id, certificate = create_certificate(client_id, client_public_key_pem)
        
        # Store certificate and public key
        certificates_db[cert_id] = certificate
        client_keys_db[client_id] = client_public_key_pem
        
        self._send_json_response(200, {
            'status': 'success',
            'message': 'Certificate issued successfully',
            'certificate_id': cert_id,
            'certificate': certificate,
            'instruction': 'Save this certificate. You will need it for secure communication.'
        })
    
    def _handle_verify(self, data):
        """Handle certificate verification"""
        if not data or 'certificate' not in data:
            self._send_json_response(400, {
                'status': 'error',
                'message': 'Required: certificate'
            })
            return
        
        cert = data['certificate']
        
        # Check required fields
        required_fields = ['certificate_id', 'subject', 'public_key', 'issued_at', 
                          'expires_at', 'issuer', 'ca_signature']
        if not all(field in cert for field in required_fields):
            self._send_json_response(400, {
                'status': 'error',
                'message': 'Invalid certificate format'
            })
            return
        
        # Extract signature
        signature = cert['ca_signature']
        
        # Recreate data that was signed
        cert_data = {k: v for k, v in cert.items() if k not in ['ca_signature', 'ca_public_key']}
        data_to_verify = json.dumps(cert_data, sort_keys=True)
        
        # Verify signature
        is_valid = verify_signature(data_to_verify, signature, ca_public_key)
        
        if not is_valid:
            self._send_json_response(400, {
                'status': 'error',
                'message': 'Certificate signature verification failed',
                'valid': False
            })
            return
        
        # Check expiration (simplified check)
        self._send_json_response(200, {
            'status': 'success',
            'message': 'Certificate verified successfully',
            'valid': True,
            'certificate_id': cert['certificate_id'],
            'subject': cert['subject'],
            'expires_at': cert['expires_at'],
            'issued_by': cert['issuer']
        })
    
    def _handle_get_cert(self, data):
        """Handle getting certificate by client ID"""
        if not data or 'client_id' not in data:
            self._send_json_response(400, {
                'status': 'error',
                'message': 'Required: client_id'
            })
            return
        
        client_id = data['client_id']
        
        print(f"\n🔍 Certificate Lookup Request:")
        print(f"   Looking for: {client_id}")
        print(f"   Registered clients: {[cert['subject'] for cert in certificates_db.values()]}")
        print(f"   Total certificates: {len(certificates_db)}")
        
        # Find certificate for this client
        for cert_id, cert in certificates_db.items():
            if cert['subject'] == client_id:
                print(f"   ✅ FOUND certificate for {client_id}")
                self._send_json_response(200, {
                    'status': 'success',
                    'certificate': cert
                })
                return
        
        print(f"   ❌ NOT FOUND: {client_id}")
        self._send_json_response(404, {
            'status': 'error',
            'message': f'No certificate found for client: {client_id}'
        })
    
    def _handle_reset(self):
        """Handle CA database reset"""
        global certificates_db, client_keys_db
        
        old_cert_count = len(certificates_db)
        old_client_count = len(client_keys_db)
        
        certificates_db.clear()
        client_keys_db.clear()
        
        self._send_json_response(200, {
            'status': 'success',
            'message': 'CA database reset successfully',
            'cleared_certificates': old_cert_count,
            'cleared_clients': old_client_count
        })
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


# ========================================
# MAIN SERVER
# ========================================

if __name__ == "__main__":
    print("=" * 60)
    print("CERTIFICATE AUTHORITY (CA) SERVER")
    print("=" * 60)
    print("\n🔐 CA Key Pair Information:")
    print(f"   Algorithm: SHA256 (simplified)")
    print(f"   Note: This is a demonstration without external libraries")
    print("\n📋 Available Endpoints:")
    print("   GET  /              - Server info")
    print("   GET  /ca/info       - Get CA public key")
    print("   POST /ca/register   - Register client & issue certificate")
    print("   POST /ca/verify     - Verify certificate authenticity")
    print("   POST /ca/get-cert   - Get certificate by client_id")
    print("   GET  /ca/certificates - List all certificates")
    print("   POST /ca/reset      - Reset database (testing only)")
    print("="*60)
    print("\n⚠️  IMPORTANT: This server can be accessed via ngrok or localtunnel")
    print("\n📝 Setup Instructions:")
    print("   Option 1 - Using ngrok:")
    print("     1. Install: winget install --id=Ngrok.Ngrok -e")
    print("     2. Run: ngrok http 5001")
    print("     3. Share the generated HTTPS URL")
    print("\n   Option 2 - Using localtunnel:")
    print("     1. Install: npm install -g localtunnel")
    print("     2. Run: lt --port 5001")
    print("     3. Share the generated URL")
    print("\n✅ CA Server starting on port 5001...")
    print("   Press Ctrl+C to stop\n")
    
    server = HTTPServer(('0.0.0.0', 5001), CAHandler)
    print(f"Server running at http://localhost:5001")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n⚠️  Server stopped by user")
        server.shutdown()
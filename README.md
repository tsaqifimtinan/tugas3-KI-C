# Public Key Infrastructure (PKI) with DES Encryption

## 📋 Overview

This project implements a complete **Public Key Certificate** system for secure distribution of DES session keys. The system combines:

- **DES encryption** for message confidentiality
- **RSA-2048** for secure key distribution
- **Digital certificates** for authentication
- **Certificate Authority (CA)** for trust management

## 🏗️ System Architecture

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Client A  │         │     CA      │         │   Client B  │
│   (Alice)   │         │   Server    │         │    (Bob)    │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                       │
       │ 1. Register & get cert│                       │
       ├──────────────────────►│                       │
       │◄──────────────────────┤                       │
       │                       │                       │
       │                       │  2. Register & get cert
       │                       │◄──────────────────────┤
       │                       ├──────────────────────►│
       │                       │                       │
       │ 3. Get Bob's cert     │                       │
       ├──────────────────────►│                       │
       │◄──────────────────────┤                       │
       │                       │                       │
       │ 4. Send encrypted msg to DES Server           │
       ├───────────────────────────────────────────────┤
       │                       │                       │
       │                       │ 5. Retrieve & decrypt │
       │                       │◄──────────────────────┤
```

## 🔐 Security Features

### 1. **Authentication**
- CA issues digital certificates that bind public keys to client identities
- Certificates are signed by CA's private key
- Prevents man-in-the-middle attacks

### 2. **Confidentiality**
- Messages encrypted with DES algorithm
- DES session key encrypted with receiver's RSA public key
- Only intended receiver can decrypt

### 3. **Integrity**
- Digital signatures prevent certificate tampering
- Certificate verification ensures authenticity

### 4. **Perfect Forward Secrecy**
- Unique random DES key for each message
- Compromise of one key doesn't affect other messages

## 📁 Project Files

```
tugas3/
├── certificate_server.py    # Certificate Authority (CA) server
├── des_server.py            # DES server with PKI support
├── des_core.py              # DES encryption/decryption functions
├── des_client.py            # PKI-enabled client application
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🚀 Installation & Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
npm install -g localtunnel
```

Required packages:
- Flask (web server)
- flask-cors (cross-origin support)
- requests (HTTP client)
- pycryptodome (cryptography)
- localtunnel (remote access)

### 2. Start the Certificate Authority Server

#### Terminal 1: CA Server
```bash
python certificate_server.py
```

#### Terminal 2: Create CA Tunnel
```bash
lt --port 5001 --subdomain ca-server-yourname
```
Copy the generated URL (e.g., `https://ca-server-yourname.loca.lt`)

### 3. Start the DES Server

#### Terminal 3: DES Server
```bash
python des_server.py
```

#### Terminal 4: Create DES Tunnel
```bash
lt --port 5002 --subdomain des-server-yourname
```
Copy the generated URL (e.g., `https://des-server-yourname.loca.lt`)

## 📖 Usage Guide

### Run the Client

#### Terminal 5: Client (e.g., Alice)
```bash
python des_client.py
```
Enter:
- Client ID: `alice`
- CA URL: Your CA localtunnel URL (e.g., `https://ca-server-yourname.loca.lt`)
- DES Server URL: Your DES localtunnel URL (e.g., `https://des-server-yourname.loca.lt`)

#### Terminal 6: Another Client (e.g., Bob)
```bash
python des_client.py
```
Enter:
- Client ID: `bob`
- CA URL: Same CA localtunnel URL
- DES Server URL: Same DES localtunnel URL

### Automatic Registration

When each client starts:
1. Client generates RSA-2048 key pair (public + private)
2. Client sends public key to CA
3. CA creates and signs a digital certificate
4. Client receives certificate (proof of identity)

### Send Secure Message (Alice → Bob)

**On Alice's terminal:**
1. Choose option `1` (Send Secure Message)
2. Enter receiver: `bob`
3. Enter message: `Hello Bob, this is a secret message!`

**What happens internally:**
```
1. Alice fetches Bob's certificate from CA
2. CA verifies Bob's certificate signature
3. Alice generates random DES session key
4. Alice encrypts message with DES key
5. Alice encrypts DES key with Bob's RSA public key (from certificate)
6. Alice sends encrypted message + encrypted key to DES server
7. DES server stores everything and returns message_id
```

### Step 4: Receive Secure Message (Bob)

**On Bob's terminal:**
1. Choose option `2` (Receive Secure Message)
2. Enter the `message_id` that Alice shared

**What happens internally:**
```
1. Bob retrieves encrypted message from DES server
2. CA verifies Bob's certificate
3. Server confirms Bob is the intended receiver
4. Bob decrypts DES session key using his RSA private key
5. Bob decrypts message using recovered DES key
6. Bob sees the plaintext message
```

## 🔍 How Public Key Certificates Work

### Certificate Structure

```json
{
  "certificate_id": "a1b2c3d4e5f6",
  "subject": "alice",
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "issued_at": "2024-11-16T10:30:00",
  "expires_at": "2025-11-16T10:30:00",
  "issuer": "Trusted Certificate Authority",
  "ca_signature": "base64_encoded_signature..."
}
```

### Certificate Verification Process

1. **Extract certificate data** (all fields except signature)
2. **Hash the data** using SHA-256
3. **Verify signature** using CA's public key
4. **Check expiration** date
5. If all checks pass → certificate is authentic

### Key Distribution Protocol

```
Alice wants to send message to Bob:

1. Alice → CA: "Give me Bob's certificate"
2. CA → Alice: Bob's certificate (contains Bob's public key)
3. Alice verifies certificate signature with CA's public key
4. Alice generates random DES key (e.g., "A1B2C3D4E5F6G7H8")
5. Alice encrypts message with DES key
6. Alice encrypts DES key with Bob's RSA public key
7. Only Bob's private key can decrypt the DES key
8. Only the DES key can decrypt the message
```

## 🔬 Testing the System

### Test Scenario 1: Normal Communication

**Alice sends to Bob:**
```
Message: "Meet me at 3pm"
Result: ✅ Success - Bob receives "Meet me at 3pm"
```

### Test Scenario 2: Wrong Receiver

**Alice sends to Bob, but Charlie tries to receive:**
```
Result: ❌ Error - "You are not the intended receiver"
```

### Test Scenario 3: Tampered Certificate

**Alice modifies Bob's certificate:**
```
Result: ❌ Error - "Invalid certificate signature"
```

### Test Scenario 4: Wrong Private Key

**Bob uses wrong private key:**
```
Result: ❌ Error - "Failed to decrypt session key"
```

## 📊 API Endpoints

### Certificate Authority (Port 5001)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ca/info` | Get CA's public key |
| POST | `/ca/register` | Register client & get certificate |
| POST | `/ca/verify` | Verify certificate authenticity |
| POST | `/ca/get-cert` | Get certificate by client_id |
| GET | `/ca/certificates` | List all issued certificates |

### DES Server (Port 5002)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Server information |
| POST | `/send-secure` | Send encrypted message with PKI |
| POST | `/receive-secure` | Receive and decrypt message |
| GET | `/messages` | List all stored messages |

## 🛡️ Security Analysis

### What This System Prevents

✅ **Eavesdropping**: Message encrypted with DES  
✅ **Key Interception**: DES key encrypted with RSA  
✅ **Identity Spoofing**: Certificates prove identity  
✅ **Man-in-the-Middle**: CA verifies all certificates  
✅ **Replay Attacks**: Unique session key per message  

### Potential Improvements

1. **Certificate Revocation**: Add CRL (Certificate Revocation List)
2. **Key Expiration**: Automatic key rotation
3. **Multi-level CA**: Root CA + Intermediate CAs
4. **Hardware Security**: Store private keys in HSM
5. **Perfect Forward Secrecy**: Ephemeral keys with Diffie-Hellman

## 🎓 Educational Value

This implementation demonstrates:

1. **Public Key Infrastructure (PKI)** fundamentals
2. **Digital certificates** and trust chains
3. **Hybrid encryption** (symmetric + asymmetric)
4. **Key distribution problem** and its solution
5. **Certificate-based authentication**

## 📝 Assignment Context

**Course**: Information Security (Keamanan Informasi)  
**Assignment**: Task 3 (Tugas 3)  
**Topic**: Public Key Distribution using Certificates  
**Implementation**: DES + RSA + Digital Certificates  

## 🔧 Troubleshooting

### Problem: "Connection refused"
**Solution**: 
1. Make sure both servers are running (CA + DES)
2. Ensure localtunnel is active for both ports
3. Use the HTTPS localtunnel URLs, not localhost

### Problem: "Certificate not found"
**Solution**: Ensure both clients have registered with CA using the same localtunnel URLs

### Problem: "Import error"
**Solution**: Install requirements: 
```bash
pip install -r requirements.txt
npm install -g localtunnel
```

### Problem: "Tunnel disconnected"
**Solution**: 
1. Restart the localtunnel command
2. Update clients with new tunnel URL
3. Consider using `--subdomain` for consistent URLs

### Problem: "Server URLs required"
**Solution**: You must provide localtunnel URLs (not localhost) when running the client

## 🌐 Remote Access

This system is designed to work over the internet using **localtunnel**:

1. **Start servers locally** on ports 5001 and 5002
2. **Create tunnels** with `lt --port 5001` and `lt --port 5002`
3. **Share tunnel URLs** with remote clients
4. **Clients connect** from anywhere using HTTPS URLs

See `LOCALTUNNEL_SETUP.md` for detailed setup instructions.

## 📚 References

- **DES Algorithm**: FIPS 46-3 (Data Encryption Standard)
- **RSA Encryption**: PKCS#1 v2.2 (RSA Cryptography Standard)
- **Digital Signatures**: PKCS#1 v1.5
- **PKI Standards**: X.509 Certificate Format (simplified version)

## 👨‍💻 Author

**Ahmad Tsaqif**  
Keamanan Informasi - Tugas 3  
Implementation Date: November 2025

---

**Note**: This is an educational implementation. For production use, consider:
- Using established PKI libraries (OpenSSL, cryptography)
- Implementing certificate chains
- Adding certificate revocation
- Using stronger encryption (AES-256 instead of DES)
- Storing private keys securely (never transmit over network)

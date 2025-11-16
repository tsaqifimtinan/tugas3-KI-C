# 🚀 Quick Setup Guide - LocalTunnel-Based PKI System

## Overview

This PKI system **requires localtunnel** for all client connections. Localhost access has been removed to focus on internet-based secure communication.

---

## ⚡ Quick Start (4 Terminals Required)

### Terminal 1: CA Server
```bash
python certificate_server.py
```
Wait for: `✅ CA Server starting on port 5001...`

### Terminal 2: CA Tunnel
```bash
lt --port 5001 --subdomain ca-yourname
```
Copy the URL: `https://ca-yourname.loca.lt` ✅

### Terminal 3: DES Server
```bash
python des_server.py
```
Wait for: `✅ Server starting on port 5002...`

### Terminal 4: DES Tunnel
```bash
lt --port 5002 --subdomain des-yourname
```
Copy the URL: `https://des-yourname.loca.lt` ✅

---

## 👤 Client Usage

### Terminal 5+: Run Clients
```bash
python des_client.py
```

**When prompted, enter:**
- Client ID: `alice` (or any name)
- CA Server URL: `https://ca-yourname.loca.lt` (from Terminal 2)
- DES Server URL: `https://des-yourname.loca.lt` (from Terminal 4)

⚠️ **Important:** You MUST use the localtunnel URLs (not localhost)

---

## 🧪 Testing

### Update Test Script First

Edit `test_pki_system.py`:
```python
CA_URL = "https://ca-yourname.loca.lt"    # Update this
DES_URL = "https://des-yourname.loca.lt"  # Update this
```

### Run Tests
```bash
python test_pki_system.py
```

---

## 📋 Complete Setup Checklist

- [ ] Install Python dependencies: `pip install -r requirements.txt`
- [ ] Install localtunnel: `npm install -g localtunnel`
- [ ] Start CA server (Terminal 1)
- [ ] Create CA tunnel (Terminal 2) → Copy URL
- [ ] Start DES server (Terminal 3)
- [ ] Create DES tunnel (Terminal 4) → Copy URL
- [ ] Update test script with tunnel URLs
- [ ] Run client with tunnel URLs

---

## 🎯 Example Session

**Setup Phase:**
```
Terminal 1: python certificate_server.py
Terminal 2: lt --port 5001 --subdomain ca-tsaqif
            → https://ca-tsaqif.loca.lt

Terminal 3: python des_server.py
Terminal 4: lt --port 5002 --subdomain des-tsaqif
            → https://des-tsaqif.loca.lt
```

**Client Phase (Alice):**
```
Terminal 5: python des_client.py
            Client ID: alice
            CA URL: https://ca-tsaqif.loca.lt
            DES URL: https://des-tsaqif.loca.lt
```

**Client Phase (Bob):**
```
Terminal 6: python des_client.py
            Client ID: bob
            CA URL: https://ca-tsaqif.loca.lt
            DES URL: https://des-tsaqif.loca.lt
```

**Communication:**
- Alice sends message to Bob
- Bob receives using Message ID
- Both can communicate securely over the internet!

---

## 🔧 Troubleshooting

### "Server URLs are required!"
→ You must enter the localtunnel URLs when prompted

### "Connection refused"
→ Check that all 4 terminals are running (2 servers + 2 tunnels)

### "Tunnel session failed"
→ Subdomain taken, try a different name or omit `--subdomain`

### Tunnel keeps disconnecting
→ Check internet connection or try ngrok as alternative

---

## 🌐 Why LocalTunnel Only?

1. **Real-world simulation**: Practice internet-based PKI
2. **Remote collaboration**: Share servers with classmates
3. **Testing flexibility**: Test from different networks
4. **Assignment focus**: Demonstrate distributed security

---

## 📚 Additional Documentation

- **Full details**: See `README.md`
- **LocalTunnel guide**: See `LOCALTUNNEL_SETUP.md`
- **Architecture**: See `ARCHITECTURE.md`

---

## ⏱️ Typical Timeline

| Step | Time | Terminal |
|------|------|----------|
| Install dependencies | 2 min | Any |
| Start CA server | 5 sec | 1 |
| Create CA tunnel | 10 sec | 2 |
| Start DES server | 5 sec | 3 |
| Create DES tunnel | 10 sec | 4 |
| Run client (Alice) | 30 sec | 5 |
| Run client (Bob) | 30 sec | 6 |
| **Total** | **~4 min** | **6 terminals** |

---

## 🎓 Key Learning Outcomes

✅ Public Key Infrastructure (PKI)  
✅ Digital Certificates & Trust  
✅ Hybrid Encryption (DES + RSA)  
✅ Internet-based Secure Communication  
✅ Certificate-based Authentication  

---

**Ready to start? Open Terminal 1 and run:** `python certificate_server.py` 🚀

# LocalTunnel Setup Guide

## 🌐 Internet-Based PKI System

This PKI system is designed to work over the internet using **LocalTunnel**. All clients must connect using localtunnel URLs for secure remote communication.

## 📋 Prerequisites

1. **Node.js and npm** installed
   - Download from: https://nodejs.org/
   - Verify: `node --version` and `npm --version`

2. **Python dependencies** installed
   - Run: `pip install -r requirements.txt`

## 🚀 Quick Setup

### Step 1: Install LocalTunnel

```bash
npm install -g localtunnel
```

Verify installation:
```bash
lt --version
```

### Step 2: Start Your Servers

**Terminal 1 - CA Server:**
```bash
python certificate_server.py
```

**Terminal 2 - DES Server:**
```bash
python des_server.py
```

### Step 3: Create Tunnels

**Terminal 3 - CA Tunnel:**
```bash
lt --port 5001 --subdomain ca-yourname
```

Example output:
```
your url is: https://ca-yourname.loca.lt
```

**Terminal 4 - DES Tunnel:**
```bash
lt --port 5002 --subdomain des-yourname
```

Example output:
```
your url is: https://des-yourname.loca.lt
```

**Note:** If subdomain is taken, localtunnel will assign a random one. Try different names or omit `--subdomain` to get a random URL.

⚠️ **IMPORTANT:** You must use these localtunnel URLs (not localhost) when running clients!

### Step 4: Run Client

When running `des_client.py`, **you must use the tunnel URLs**:

```python
# Required format:
CA Server URL: https://ca-yourname.loca.lt
DES Server URL: https://des-yourname.loca.lt
```

**Note:** Localhost URLs will not work - the system requires localtunnel URLs.

## 🔧 Alternative: Using ngrok

If you prefer ngrok (requires signup):

### Install ngrok
```bash
# Download from: https://ngrok.com/download
# Or use chocolatey:
choco install ngrok
```

### Create Tunnels

**Terminal 3 - CA Tunnel:**
```bash
ngrok http 5001
```

**Terminal 4 - DES Tunnel:**
```bash
ngrok http 5002
```

Copy the `https://` URLs from the ngrok output.

## 📱 Testing Remote Access

### Test CA Server
```bash
curl https://ca-yourname.loca.lt/ca/info
```

### Test DES Server
```bash
curl https://des-yourname.loca.lt/
```

## 🛡️ Security Considerations

### For Development/Testing:
✅ Use localtunnel or ngrok  
✅ Share URLs only with trusted parties  
✅ Monitor server logs for suspicious activity  

### For Production:
❌ **DO NOT use localtunnel in production**  
✅ Deploy to cloud services (AWS, Azure, GCP)  
✅ Use proper SSL certificates  
✅ Implement rate limiting  
✅ Add authentication/authorization  
✅ Use environment variables for sensitive data  

## 📝 Example Client Usage

### Scenario: Alice and Bob on Different Networks

**Alice's Setup:**
1. Runs CA and DES servers locally
2. Creates localtunnel URLs:
   - `https://ca-alice.loca.lt`
   - `https://des-alice.loca.lt`
3. Shares URLs with Bob

**Bob's Setup:**
1. Runs `python des_client.py`
2. Enters Alice's tunnel URLs
3. Registers and communicates securely

### Full Example Session

**Bob's Client:**
```
$ python des_client.py

====================================================
     PKI-ENABLED SECURE MESSAGING CLIENT
====================================================

🔧 CLIENT SETUP
⚠️  Use localtunnel URLs (e.g., https://ca-server-yourname.loca.lt)

Enter your client ID: bob
CA Server URL: https://ca-alice.loca.lt
DES Server URL: https://des-alice.loca.lt

🔐 Generating RSA key pair for bob...
✅ Keys generated successfully!

📝 Registering with Certificate Authority...
✅ Certificate issued successfully!
   Certificate ID: a2b3c4d5
   Valid until: 2025-11-16T10:30:00
```

## 🔍 Troubleshooting

### Issue: "Tunnel session failed"
**Solution:** The subdomain might be taken. Try a different name or omit `--subdomain`:
```bash
lt --port 5001
```

### Issue: "CORS error" in browser
**Solution:** The Flask servers already have CORS enabled. If issues persist:
1. Check that `flask-cors` is installed: `pip install flask-cors`
2. Restart the servers

### Issue: "Connection refused"
**Solution:** 
1. Ensure servers are running on 0.0.0.0 (not 127.0.0.1)
2. Check if ports 5001/5002 are available
3. Verify tunnel is pointing to correct port

### Issue: "SSL certificate error"
**Solution:** LocalTunnel uses HTTPS with self-signed certs. In Python requests:
```python
# Add verify=False for localtunnel (dev only!)
response = requests.get(url, verify=False)
```

Or install the certificate authority:
```python
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

### Issue: Tunnel keeps disconnecting
**Solution:**
1. Use stable internet connection
2. Consider using ngrok (more stable but requires signup)
3. Run tunnel with `--print-requests` to debug:
   ```bash
   lt --port 5001 --print-requests
   ```

## 📊 Monitoring

### Check Active Connections
LocalTunnel provides a web interface at:
```
https://loca.lt/inspect?id=<your-tunnel-id>
```

### Server Logs
Monitor your Python servers for incoming requests:
- CA Server: Shows registration attempts
- DES Server: Shows encryption/decryption operations

## 🎯 Production Deployment Alternatives

For real-world deployment, consider:

### 1. Cloud VM (AWS EC2, Azure VM, Google Compute)
```bash
# Install dependencies
sudo apt update
sudo apt install python3-pip

# Setup firewall
sudo ufw allow 5001
sudo ufw allow 5002

# Run with systemd service
sudo systemctl start ca-server
sudo systemctl start des-server
```

### 2. Container Deployment (Docker)
```dockerfile
FROM python:3.12
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5001
CMD ["python", "certificate_server.py"]
```

### 3. Serverless (AWS Lambda, Azure Functions)
- Use API Gateway for HTTP endpoints
- Store certificates in database (DynamoDB, CosmosDB)
- Use managed secrets (AWS Secrets Manager, Azure Key Vault)

## 🔗 Useful Links

- **LocalTunnel:** https://theboroer.github.io/localtunnel-www/
- **ngrok:** https://ngrok.com/
- **Flask CORS:** https://flask-cors.readthedocs.io/
- **Testing APIs:** https://www.postman.com/ or https://hoppscotch.io/

## 💡 Tips

1. **Custom subdomain:** Use your name or project identifier
   ```bash
   lt --port 5001 --subdomain pki-yourname
   ```

2. **Multiple connections:** Run separate tunnel processes for each port

3. **Keep URLs consistent:** Use environment variables or config files:
   ```python
   import os
   CA_URL = os.getenv('CA_URL', 'http://localhost:5001')
   DES_URL = os.getenv('DES_URL', 'http://localhost:5002')
   ```

4. **Share safely:** Only share tunnel URLs in secure channels

5. **Restart on disconnect:** Use a process manager like `pm2`:
   ```bash
   npm install -g pm2
   pm2 start "lt --port 5001" --name ca-tunnel
   pm2 start "lt --port 5002" --name des-tunnel
   ```

---

**Remember:** LocalTunnel is perfect for development, demos, and testing. For production, use proper cloud hosting with SSL certificates and security best practices! 🔒

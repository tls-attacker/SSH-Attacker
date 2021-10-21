# Supported Algorithms

---
## Supported Key Exchange Algorithms

- `diffie-hellman-group-exchange-sha1`
- `diffie-hellman-group-exchange-sha256`
- `diffie-hellman-group1-sha1`
- `diffie-hellman-group14-sha1`
- `diffie-hellman-group14-sha256`
- `diffie-hellman-group15-sha512`
- `diffie-hellman-group16-sha512`
- `diffie-hellman-group17-sha512`
- `diffie-hellman-group18-sha512`
- `ecdh-sha2-nistp256`
- `ecdh-sha2-nistp384`
- `ecdh-sha2-nistp521`
- `ecdh-sha2-*` (where * is a secp, sect or Brainpool curves' OID)
- `curve25519-sha256`
- `curve25519-sha256@libssh.org`
- `curve448-sha512`
---
## Supported Cipher Algorithms

- `3des-cbc`
- `aes256-cbc`
- `aes192-cbc`
- `aes128-cbc`
- `aes256-ctr`
- `aes192-ctr`
- `aes128-ctr`

**Untested**:

- `arcfour`
- `arcfour128`
- `arcfour256`
- `blowfish-cbc`
- `blowfish-ctr`
- `des-cbc`
- `3des-ctr`
---
## Supported MAC Algorithms

- `hmac-sha1`
- `hmac-sha1-96`
- `hmac-sha256`
- `hmac-sha512`
- `hmac-sha1-etm@openssh.com`
- `hmac-sha1-96-etm@openssh.com`
- `hmac-sha256-etm@openssh.com`
- `hmac-sha512-etm@openssh.com`
---
## Supported Host Key Algorithms

- `ssh-rsa`
---
## Supported Compression Algorithms

- `none`
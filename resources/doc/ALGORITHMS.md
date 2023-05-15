# Supported Algorithms

---

## Supported Key Exchange Algorithms

- `diffie-hellman-group-exchange-sha1`
- `diffie-hellman-group-exchange-sha224@ssh.com`
- `diffie-hellman-group-exchange-sha256`
- `diffie-hellman-group-exchange-sha384@ssh.com`
- `diffie-hellman-group-exchange-sha512@ssh.com`
- `diffie-hellman-group1-sha1`
- `diffie-hellman-group14-sha1`
- `diffie-hellman-group14-sha224@ssh.com`
- `diffie-hellman-group14-sha256`
- `diffie-hellman-group14-sha256@ssh.com`
- `diffie-hellman-group15-sha256@ssh.com`
- `diffie-hellman-group15-sha384@ssh.com`
- `diffie-hellman-group15-sha512`
- `diffie-hellman-group16-sha384@ssh.com`
- `diffie-hellman-group16-sha512`
- `diffie-hellman-group16-sha512@ssh.com`
- `diffie-hellman-group17-sha512`
- `diffie-hellman-group18-sha512`
- `diffie-hellman-group18-sha512@ssh.com`
- `ecdh-sha2-nistp256`
- `ecdh-sha2-nistp384`
- `ecdh-sha2-nistp521`
- `ecdh-sha2-*` (where * is a secp, sect or Brainpool curves' OID)
- `curve25519-sha256`
- `curve25519-sha256@libssh.org`
- `curve448-sha512`
- `sntrup761x25519-sha512@openssh.com`

---

## Supported Encryption Algorithms

- `3des-{cbc|ctr}`
- `AEAD_AES_{128|256}_GCM`
- `AEAD_CAMELLIA_{128|256}_GCM` (not registered with IANA)
- `aes{128|192|256}-{cbc|ctr}`
- `aes{128|256}-gcm@openssh.com`
- `arcfour`
- `arcfour{128|256}`
- `blowfish-{cbc|ctr}`
- `camellia{128|192|256}-{cbc|ctr}` (not registered with IANA)
- `camellia{128|192|256}-{cbc|ctr}@openssh.org`
- `cast128-{cbc|ctr}`
- `des-cbc`
- `idea-{cbc|ctr}`
- `none`
- `seed-cbc@ssh.com`
- `rijndael-cbc@lysator.liu.se`
- `serpent{128|192|256}-{cbc|ctr}`
- `serpent{128|256}-gcm@libassh.org`
- `twofish{128|192|256}-{cbc|ctr}`
- `twofish{128|256}-gcm@libassh.org`

---

## Supported MAC Algorithms

- `AEAD_AES_{128|256}_GCM`
- `AEAD_AES_256_GCM`
- `hmac-md5`
- `hmac-md5-96`
- `hmac-md5-etm@openssh.com`
- `hmac-md5-96-etm@openssh.com`
- `hmac-sha1`
- `hmac-sha1-96`
- `hmac-sha1-etm@openssh.com`
- `hmac-sha1-96-etm@openssh.com`
- `hmac-sha{256|512}`
- `hmac-sha{256|512}-etm@openssh.com`
- `umac-{32|64|96|128}@openssh.com`
- `umac-{32|64|96|128}-etm@openssh.com`
- `none`

---

## Supported Host Key Algorithms

- `ssh-rsa`
- `ssh-dss`
- `rsa-sha2-{256|256}`
- `ecdsa-sha2-nistp256`
- `ecdsa-sha2-nistp384`
- `ecdsa-sha2-nistp521`
- `ecdsa-sha2-*` (where * is a secp, sect or Brainpool curves' OID)
- `ssh-ed25519`
- `ssh-ed448`
- `ssh-rsa-sha{224|256|384|512}@ssh.com`

---

## Supported Compression Methods

- `none`
- `zlib`
- `zlib@openssh.com`


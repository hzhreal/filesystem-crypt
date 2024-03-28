# filesystem-crypt
This script encrypts/decrypts all files in the current directory, and those below.

## Encryption
- User inputs AES key and HMAC SHA1 key
- Key gets hashed repeatedly using SHA256
- Random nonce gets calculated using secrets library
- Original data gets hashed using HMAC SHA1
- Data gets encrypted using AES256-GCM
- The encrypted file is structured as follows: Nonce - Data - HMAC SHA1 hash

## Decryption
- User inputs AES key and HMAC SHA1 key
- Key gets hashed repeatedly using SHA256
- Nonce gets obtained from the start of the file
- Data gets decrypted using AES256-GCM
- Decrypted data gets hashed using HMAC SHA1
- If the checksums does not match, the file will be skipped, with no changes to it
- If the checksums match, the file gets decrypted

## Constants
N_ROUND: How many times you want to hash the AES- and HMAC SHA1 key
NONCE_LEN: The length of the nonce in bytes

If the same values are not used the decryption will fail.

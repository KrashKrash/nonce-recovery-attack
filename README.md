# nonce-recovery-attack
This is a nonce k recovery program. it uses a brute force technique to get the correct nonce k in the ECDSA SECP256k1 Curve which is implemented in Bitcoin and Etherum. All you need to give as input is the R,S,Z signature and public key in hexadecimal. ie: 0x123456abcd
What is great about this program is that it stores all the k nonce thats been used to guess the correct nonce so that if you accidentally close the program, it wont restart from the same keys that was used. it will continue from where you left off.

If you like this program, donate to Bitcoin Address: 3MNAKj3xjJRRjfMtdSfgNZsKAYXjSNeXtg

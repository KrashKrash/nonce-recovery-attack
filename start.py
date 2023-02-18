import ecdsa
import time
import os
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from hashlib import sha256

def nonce_recovery(r, s, z, k_guess, public_key_bytes):
    public_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1).to_string()[:32]
    private_key = SigningKey.from_string(public_key, curve=SECP256k1)
    
    # Load previous guesses from a file if it exists
    previous_guesses = set()
    if os.path.exists('previous_guesses.txt'):
        with open('previous_guesses.txt', 'r') as f:
            previous_guesses = set(int(line.strip()) for line in f)
    
    # Load the last guess from a file if it exists, otherwise use the supplied guess
    if os.path.exists('last_guess.txt'):
        with open('last_guess.txt', 'r') as f:
            k_guess = int(f.read())
    
    k_inv = pow(k_guess, -1, SECP256k1.order)
    r_inv = pow(r, -1, SECP256k1.order)
    s_inv = pow(s, -1, SECP256k1.order)
    x = ((z % SECP256k1.order) * s_inv) % SECP256k1.order
    k_guess = ((x * r_inv) % SECP256k1.order) - k_inv
    signature = (r, s)
    while True:
        # Check if the new guess has already been made before
        if k_guess in previous_guesses:
            k_guess += 1
            continue
        
        private_key = SigningKey.from_secret_exponent((k_guess % SECP256k1.order), curve=SECP256k1)
        test_signature = private_key.sign_digest(sha256(str(z).encode()).digest(), sigencode=ecdsa.util.sigencode_der)
        if test_signature == signature:
            return k_guess
        
        # Store the guess in the set of previous guesses
        previous_guesses.add(k_guess)
        
        # Store the last guess in a file
        with open('last_guess.txt', 'w') as f:
            f.write(str(k_guess))
            
        k_guess += 1
        
        # Print progress
        if k_guess % 5 == 0:
            print(f"Cracking: {k_guess}")
            
        # Sleep for a short time to avoid overwhelming the console
        time.sleep(0.01)

# Example usage:
r = 0x00e1de2aea5f0b8e2d97f244b5a4e14e6752d88ca46d8821777e9
s = 0x1dd566fb377bd782af7de11dad9ff552746eeeadcde
z = 0xabfe106fb5873c5419cf2265da1c5f02d1aa77c4f
k_guess = 1000000000
public_key= bytes.fromhex('0245a6b3f8eeab8e88501a9a25391318dce9bf36')
result = nonce_recovery(r, s, z, k_guess, public_key)
print(result)

import ecdsa
import time
import os
import sys
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der
from hashlib import sha256

def nonce_recovery(r, s, z, k_guess, public_key_bytes):
    """
    Brute force a nonce (k) used in ECDSA signature generation by testing sequential values.
    
    Args:
        r, s: Signature components
        z: Message hash
        k_guess: Initial guess for the nonce to start brute forcing from
        public_key_bytes: The public key in bytes
    
    Returns:
        Recovered nonce if successful
    """
    # Load previous guesses from a file if it exists
    previous_guesses = set()
    if os.path.exists('previous_guesses.txt'):
        with open('previous_guesses.txt', 'r') as f:
            for line in f:
                try:
                    previous_guesses.add(int(line.strip()))
                except ValueError:
                    continue  # Skip invalid lines
    
    # Load the last guess from a file if it exists, otherwise use the supplied guess
    if os.path.exists('last_guess.txt'):
        try:
            with open('last_guess.txt', 'r') as f:
                k_guess = int(f.read().strip())
                print(f"Resuming from: 0x{k_guess:x}        ", end="\r")
        except (ValueError, IOError):
            pass
    
    try:
        # Verify the public key
        VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
    except Exception as e:
        print(f"\nError: Invalid public key - {e}")
        return None
    
    # Ensure r and s are within the valid range for the curve
    n = SECP256k1.order
    if not (1 <= r < n and 1 <= s < n):
        print(f"\nError: Invalid signature parameters")
        return None
    # Print header only once at the beginning
    print(f"\n{'=' * 80}")
    print(f"ECDSA NONCE BRUTE FORCE RECOVERY TOOL v1.0")
    print(f"{'=' * 80}")
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] OPERATION STARTED")
    print(f"  ├─ Target r-value: 0x{r:x}")
    print(f"  ├─ Target s-value: 0x{s:x}")
    print(f"  ├─ Message hash: 0x{z:x}")
    print(f"  └─ Starting value for brute force: 0x{k_guess:x}")
    print(f"{'-' * 80}")
    
    # Print initial status line that will be updated with \r
    print("Status: Initializing...", end="\r")
    # Load the verifying key properly from the provided public key bytes
    try:
        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
    except Exception as e:
        print(f"Critical Error: Failed to load public key: {str(e)}")
        
        # Log error to file
        with open('error.log', 'a') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] PUBLIC KEY ERROR: {str(e)}\n")
            f.write(f"  Public key bytes: {public_key_bytes.hex()}\n")
        
        return None
    
    # Load previous guesses from a file if it exists
    previous_guesses = set()
    if os.path.exists('previous_guesses.txt'):
        with open('previous_guesses.txt', 'r') as f:
            for line in f:
                try:
                    previous_guesses.add(int(line.strip()))
                except ValueError:
                    continue  # Skip invalid lines
    
    # Load the last guess from a file if it exists, otherwise use the supplied guess
    if os.path.exists('last_guess.txt'):
        try:
            with open('last_guess.txt', 'r') as f:
                k_guess = int(f.read().strip())
                print(f"Resuming from checkpoint: 0x{k_guess:x}", end="\r")
                time.sleep(1)  # Brief pause to show the resume message
        except (ValueError, IOError) as e:
            print(f"Warning: Checkpoint corrupted. Using initial value.", end="\r")
            time.sleep(1)  # Brief pause to show the warning
    
    # Create DER signature from r and s for comparison
    try:
        # Ensure r and s are within the valid range for the curve
        n = SECP256k1.order
        if not (1 <= r < n and 1 <= s < n):
            print(f"Error: Invalid signature parameters (r: 0x{r:x}, s: 0x{s:x})")
            
            # Log error to file
            with open('error.log', 'a') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] PARAMETER ERROR: Invalid r or s values\n")
                f.write(f"  r: 0x{r:x}, s: 0x{s:x}, valid range: 1 to 0x{n-1:x}\n")
                
            return None
            
        original_signature = sigencode_der(r, s, n)
    except Exception as e:
        print(f"Error: Failed to create DER signature: {str(e)}")
        
        # Log error to file
        with open('error.log', 'a') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SIGNATURE ERROR: {str(e)}\n")
            
        return None
    
    counter = 0
    start_time = time.time()
    total_start_time = start_time
    estimated_values = 0
    
    while True:
        # Check if the new guess has already been made before
        if k_guess in previous_guesses:
            k_guess += 1
            continue
        
        try:
            # Generate a private key from the guessed nonce
            private_key = SigningKey.from_secret_exponent(k_guess, curve=SECP256k1)
            
            # Sign the message digest with this private key
            message_digest = sha256(str(z).encode()).digest()
            test_signature = private_key.sign_digest(message_digest, sigencode=sigencode_der)
            
            # Decode the test signature to get r and s values
            test_r, test_s = sigdecode_der(test_signature, n)
            
            # Check if the r value matches (sufficient for nonce recovery)
            if test_r == r:
                # Store the successful guess
                with open('successful_guess.txt', 'w') as f:
                    f.write(str(k_guess))
                
                # Print success message after clearing the status line
                print(" " * 100, end="\r")  # Clear the status line
                print(f"\n{'=' * 80}")
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SUCCESS: NONCE FOUND")
                print(f"  ├─ Recovered nonce (k): 0x{k_guess:x}")
                print(f"  ├─ Decimal value: {k_guess}")
                print(f"  ├─ Total operations: {estimated_values:,}")
                print(f"  └─ Result saved to: successful_guess.txt")
                print(f"{'=' * 80}\n")
                
                return k_guess
        except Exception as e:
            # Log errors to file instead of printing to console
            with open('error.log', 'a') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ERROR at k=0x{k_guess:x}: {str(e)}\n")
            # Continue with the next guess
        
        # Store the guess in the set of previous guesses
        previous_guesses.add(k_guess)
        
        # Periodically save progress to file
        counter += 1
        if counter % 1000 == 0:
            with open('last_guess.txt', 'w') as f:
                f.write(str(k_guess))
            with open('previous_guesses.txt', 'a') as f:
                for i in range(counter):
                    if k_guess - i not in previous_guesses:
                        break
                    f.write(f"{k_guess - i}\n")
            
                    # Create single-line status with carriage return to update in place
            elapsed = time.time() - start_time
            rate = counter / elapsed if elapsed > 0 else 0
            total_elapsed = time.time() - total_start_time
            
            # Format time as hh:mm:ss
            hours, remainder = divmod(total_elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            time_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
            
            # Create status line with padding to ensure it overwrites previous line completely
            status = f"[{time_str}] Testing: 0x{k_guess:x} | Speed: {rate:,.2f} op/s | Completed: {estimated_values:,}      "
            
            # Print status with carriage return to update in place
            print(status, end="\r")
            
        k_guess += 1
        
        # Smaller sleep to maintain performance
        if counter % 10000 == 0:
            time.sleep(0.001)  # Brief pause to prevent CPU overload

if __name__ == "__main__":
    # Print header
    print("\nECDSA NONCE RECOVERY TOOL v2.0")
    print("===============================\n")
    
    # Example usage with proper hex values
    r = 0x00e1de2aea5f0b8e2d97f244b5a4e14e6752d88ca46d8821777e9
    s = 0x1dd566fb377bd782af7de11dad9ff552746eeeadcde
    z = 0xabfe106fb5873c5419cf2265da1c5f02d1aa77c4f
    k_guess = 1000000000
    
    # Display input parameters once
    print(f"Target r: 0x{r:x}")
    print(f"Target s: 0x{s:x}")
    print(f"Message hash: 0x{z:x}")
    print(f"Starting from: 0x{k_guess:x}\n")
    
    # Initialize status line
    print("Status: ", end="")
    sys.stdout.flush()
    
    # Public key should be properly formatted
    try:
        # The example public key was too short - using a placeholder instead
        # In a real scenario, you would use the actual 33 or 65 byte public key
        public_key_bytes = bytes.fromhex('0245a6b3f8eeab8e88501a9a25391318dce9bf3600000000000000000000000000000000000000000000000000000000000000')[:33]
        
        result = nonce_recovery(r, s, z, k_guess, public_key_bytes)
        if result:
            print(f"\nSuccess! Nonce recovered: 0x{result:x}")
        else:
            print("\nFailed to recover nonce")
    except Exception as e:
        print(f"\nError: {e}")

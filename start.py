#!/usr/bin/env python3
"""
ECDSA Nonce Recovery Tool v4.0
This tool brute-forces the nonce (k) used in ECDSA signature generation.
"""

import os
import sys
import time
import logging
import argparse
import multiprocessing as mp
from datetime import timedelta
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("nonce_recovery.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("nonce_recovery")

try:
    # We'll use fastecdsa for better performance and fewer C conversion issues
    from fastecdsa import curve
    from fastecdsa.point import Point
    CURVE = curve.secp256k1
    USING_FASTECDSA = True
except ImportError:
    # Fall back to pure Python implementation if fastecdsa is not available
    logger.warning("fastecdsa library not found, falling back to pure Python implementation")
    logger.warning("Install fastecdsa for better performance: pip install fastecdsa")
    USING_FASTECDSA = False
    
    # Pure Python implementation of the secp256k1 curve
    class PurePython_SECP256k1:
        """Pure Python implementation of secp256k1 curve parameters"""
        # Curve parameters for secp256k1
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        a = 0
        b = 7
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        
        @staticmethod
        def point_add(p1, p2):
            """Add two points on the curve"""
            if p1 is None:
                return p2
            if p2 is None:
                return p1
                
            x1, y1 = p1
            x2, y2 = p2
            
            # Handle point at infinity
            if x1 is None:
                return x2, y2
            if x2 is None:
                return x1, y1
                
            # Same x-coordinate means either same point or inverse
            if x1 == x2:
                if (y1 + y2) % PurePython_SECP256k1.p == 0:
                    return None  # Point at infinity
                # Point doubling
                lam = (3 * x1 * x1) * pow(2 * y1, -1, PurePython_SECP256k1.p) % PurePython_SECP256k1.p
            else:
                # Different points
                lam = (y2 - y1) * pow(x2 - x1, -1, PurePython_SECP256k1.p) % PurePython_SECP256k1.p
                
            x3 = (lam * lam - x1 - x2) % PurePython_SECP256k1.p
            y3 = (lam * (x1 - x3) - y1) % PurePython_SECP256k1.p
            
            return x3, y3
            
        @staticmethod
        def scalar_mult(k, point):
            """Scalar multiplication of a point"""
            if k == 0 or point is None:
                return None
                
            result = None
            addend = point
            
            while k:
                if k & 1:
                    result = PurePython_SECP256k1.point_add(result, addend)
                addend = PurePython_SECP256k1.point_add(addend, addend)
                k >>= 1
                
            return result
    
    # Use our pure Python implementation
    CURVE = PurePython_SECP256k1()


class NonceRecoveryTool:
    """ECDSA nonce (k) recovery tool that uses brute force to find the nonce used in signature generation."""
    
    def __init__(self, r, s, z, k_start=1, checkpoint_interval=1000):
        """
        Initialize the nonce recovery tool.
        
        Args:
            r (int): r component of the ECDSA signature
            s (int): s component of the ECDSA signature
            z (int): Message hash
            k_start (int): Initial value to start brute forcing from
            checkpoint_interval (int): How often to save progress
        """
        if USING_FASTECDSA:
            self.n = CURVE.q  # Order of the curve in fastecdsa
        else:
            self.n = CURVE.n  # Order of the curve in our pure Python implementation
            
        # Normalize inputs to be within curve order
        self.r = r % self.n
        self.s = s % self.n
        self.z = z % self.n
        self.k_start = k_start
        self.checkpoint_interval = checkpoint_interval
        
        # File paths for checkpointing
        self.previous_guesses_file = 'previous_guesses.txt'
        self.last_guess_file = 'last_guess.txt'
        self.successful_guess_file = 'successful_guess.txt'
        self.previous_guesses = set()  # For smaller runs, a set is fine
        
        # Validate inputs
        self._validate_inputs()
        
    def _validate_inputs(self):
        """Validate the input parameters."""
        # Ensure r and s are within the valid range for the curve
        if not (1 <= self.r < self.n and 1 <= self.s < self.n):
            logger.error(f"Invalid signature parameters (r: 0x{self.r:x}, s: 0x{self.s:x})")
            logger.error(f"Curve order: 0x{self.n:x}")
            raise ValueError(f"Invalid signature parameters (r: 0x{self.r:x}, s: 0x{self.s:x})")
    
    def _load_checkpoint(self):
        """Load previous state from checkpoint files."""
        k_guess = self.k_start
        
        # Load previous guesses
        if os.path.exists(self.previous_guesses_file):
            try:
                with open(self.previous_guesses_file, 'r') as f:
                    for line in f:
                        try:
                            self.previous_guesses.add(int(line.strip()))
                        except ValueError:
                            continue  # Skip invalid lines
                logger.info(f"Loaded {len(self.previous_guesses):,} previous guesses")
            except Exception as e:
                logger.warning(f"Error loading previous guesses: {e}")
        
        # Load last guess
        if os.path.exists(self.last_guess_file):
            try:
                with open(self.last_guess_file, 'r') as f:
                    k_guess = int(f.read().strip())
                logger.info(f"Resuming from checkpoint: 0x{k_guess:x}")
            except (ValueError, IOError) as e:
                logger.warning(f"Error loading checkpoint, using start value: {e}")
        
        return k_guess
    
    def _save_checkpoint(self, k_guess, new_guesses):
        """Save current progress to checkpoint files."""
        try:
            with open(self.last_guess_file, 'w') as f:
                f.write(str(k_guess))
            
            with open(self.previous_guesses_file, 'a') as f:
                for guess in new_guesses:
                    f.write(f"{guess}\n")
            
            logger.debug(f"Checkpoint saved at k=0x{k_guess:x}")
        except Exception as e:
            logger.warning(f"Error saving checkpoint: {e}")
    
    def _save_result(self, k_value):
        """Save successful nonce recovery result."""
        try:
            with open(self.successful_guess_file, 'w') as f:
                f.write(str(k_value))
            logger.info(f"Result saved to: {self.successful_guess_file}")
        except Exception as e:
            logger.warning(f"Error saving result: {e}")
    
    def _calculate_r_value(self, k):
        """Calculate the r value for a given k using the appropriate library."""
        if USING_FASTECDSA:
            # Use fastecdsa for better performance
            point = k * CURVE.G
            return point.x % self.n
        else:
            # Use our pure Python implementation
            G_point = (CURVE.Gx, CURVE.Gy)
            point = CURVE.scalar_mult(k, G_point)
            if point is None:
                return None
            return point[0] % self.n
    
    def _worker_process(self, start_k, chunk_size, result_queue, worker_id):
        """Worker process for parallel nonce testing."""
        logger.debug(f"Worker {worker_id} starting with range: {start_k} to {start_k + chunk_size - 1}")
        
        for k in range(start_k, start_k + chunk_size):
            try:
                # Calculate r value directly using point multiplication
                calculated_r = self._calculate_r_value(k)
                
                # Check if the r value matches
                if calculated_r == self.r:
                    result_queue.put(k)
                    return
                    
            except Exception as e:
                logger.debug(f"Worker {worker_id} error at k=0x{k:x}: {e}")
        
        # No match found in this chunk
        result_queue.put(None)
        logger.debug(f"Worker {worker_id} completed without finding match")
    
    def recover(self, use_multiprocessing=True, num_processes=None, chunk_size=1000):
        """
        Execute the nonce recovery process.
        
        Args:
            use_multiprocessing (bool): Whether to use parallel processing
            num_processes (int): Number of processes to use (None = use CPU count)
            chunk_size (int): Size of work chunks for parallel processing
            
        Returns:
            int: Recovered nonce if successful, None otherwise
        """
        logger.info(f"{'=' * 80}")
        logger.info(f"ECDSA NONCE BRUTE FORCE RECOVERY TOOL v4.0")
        logger.info(f"{'=' * 80}")
        logger.info(f"Target r-value: 0x{self.r:x}")
        logger.info(f"Target s-value: 0x{self.s:x}")
        logger.info(f"Message hash: 0x{self.z:x}")
        logger.info(f"Starting value: 0x{self.k_start:x}")
        logger.info(f"Using: {'fastecdsa' if USING_FASTECDSA else 'pure Python implementation'}")
        logger.info(f"Multiprocessing: {'Enabled' if use_multiprocessing else 'Disabled'}")
        if use_multiprocessing:
            if num_processes is None:
                num_processes = min(mp.cpu_count(), 8)  # Limit to 8 processes by default
            logger.info(f"Processes: {num_processes}")
        logger.info(f"{'-' * 80}")
        
        # Load previous state
        k_guess = self._load_checkpoint()
        
        # Track performance metrics
        counter = 0
        start_time = time.time()
        total_guesses = 0
        new_guesses = set()
        
        # Print initial status line
        print("Initializing nonce recovery tool...", end="\r", flush=True)
        
        # For parallel execution
        if use_multiprocessing and mp.cpu_count() > 1:
            if num_processes is None:
                num_processes = 16  # Default to 16 processes
            
            logger.info(f"Using {num_processes} processes for parallel nonce recovery")
            
            # Pre-verify a few values to ensure our implementation works correctly
            logger.info("Verifying implementation with test values...")
            test_k = 1
            test_r = self._calculate_r_value(test_k)
            logger.info(f"Test k=1 produces r=0x{test_r:x}")
            
            while True:
                # Create chunks of work
                chunks = []
                current_k = k_guess
                
                # Create a result queue
                result_queue = mp.Queue()
                processes = []
                
                for i in range(num_processes):
                    # Skip values we've already checked
                    while current_k in self.previous_guesses:
                        current_k += 1
                    
                    # Create and start worker process
                    p = mp.Process(
                        target=self._worker_process,
                        args=(current_k, chunk_size, result_queue, i)
                    )
                    processes.append((p, current_k))
                    p.start()
                    
                    # Next chunk starts after this one
                    current_k += chunk_size
                
                # Wait for results
                found_nonce = None
                completed_processes = 0
                
                while completed_processes < len(processes):
                    try:
                        result = result_queue.get(timeout=5)  # 5 second timeout
                        completed_processes += 1
                        
                        if result is not None:
                            found_nonce = result
                            break
                    except Exception as e:
                        logger.warning(f"Error getting result from queue: {e}")
                        # Continue waiting for other processes
                
                # If we found a match, we're done
                if found_nonce is not None:
                    # Clean up processes
                    for p, _ in processes:
                        p.terminate()
                    
                    # Print a newline to clear the status line
                    print()
                    
                    total_elapsed = time.time() - start_time
                    logger.info(f"SUCCESS! Nonce found after {total_guesses:,} operations ({timedelta(seconds=int(total_elapsed))})")
                    logger.info(f"Recovered nonce (k): 0x{found_nonce:x}")
                    logger.info(f"Decimal value: {found_nonce}")
                    self._save_result(found_nonce)
                    return found_nonce
                
                # Clean up processes
                for p, _ in processes:
                    p.terminate()
                    p.join(timeout=1)  # Wait for 1 second for process to terminate
                
                # Update counters and progress
                total_checked = sum(chunk_size for _, _ in processes)
                total_guesses += total_checked
                k_guess = current_k
                
                # Update progress with carriage return printing
                elapsed = time.time() - start_time
                if elapsed > 0:
                    rate = total_guesses / elapsed
                    estimated_time = "Unknown"
                    if rate > 0:
                        # Very crude estimate (assumes linear search space)
                        remaining_iterations = min(2**32, self.n) - k_guess
                        estimated_seconds = remaining_iterations / rate
                        if estimated_seconds < 60 * 60 * 24 * 365 * 100:  # If less than 100 years
                            estimated_time = str(timedelta(seconds=int(estimated_seconds)))
                    
                    # Use carriage return to update in place
                    status = f"Progress: Testing near 0x{k_guess:x} | {rate:,.2f} keys/sec | Est. time: {estimated_time} | Total: {total_guesses:,}      "
                    print(status, end="\r", flush=True)
                
                # Save checkpoint periodically
                self._save_checkpoint(k_guess, new_guesses)
                new_guesses.clear()
                
                # Small delay to prevent CPU overload
                time.sleep(0.1)
        
        # Sequential execution
        else:
            logger.info("Using sequential (single-process) execution")
            print("Starting sequential search...", end="\r", flush=True)
            
            while k_guess < self.n:  # Stop at curve order
                # Skip values we've already checked
                if k_guess in self.previous_guesses:
                    k_guess += 1
                    continue
                
                try:
                    # Calculate r value directly
                    calculated_r = self._calculate_r_value(k_guess)
                    
                    # Check if the r value matches
                    if calculated_r == self.r:
                        # Print a newline to clear the status line
                        print()
                        
                        total_elapsed = time.time() - start_time
                        logger.info(f"SUCCESS! Nonce found after {total_guesses:,} operations ({timedelta(seconds=int(total_elapsed))})")
                        logger.info(f"Recovered nonce (k): 0x{k_guess:x}")
                        logger.info(f"Decimal value: {k_guess}")
                        self._save_result(k_guess)
                        return k_guess
                
                except Exception as e:
                    logger.debug(f"Error testing k=0x{k_guess:x}: {e}")
                
                # Track guesses
                self.previous_guesses.add(k_guess)
                new_guesses.add(k_guess)
                total_guesses += 1
                counter += 1
                
                # Checkpoint and status update
                if counter % self.checkpoint_interval == 0:
                    self._save_checkpoint(k_guess, new_guesses)
                    new_guesses.clear()
                    
                    elapsed = time.time() - start_time
                    if elapsed > 0:
                        rate = counter / elapsed
                        # Use carriage return to update in place
                        status = f"Progress: Testing 0x{k_guess:x} | {rate:,.2f} keys/sec | Completed: {total_guesses:,}        "
                        print(status, end="\r", flush=True)
                    
                    counter = 0
                    start_time = time.time()
                
                k_guess += 1
                
                # Brief pause to prevent CPU overload
                if counter % 10000 == 0:
                    time.sleep(0.001)
        
        logger.error("Nonce recovery failed - reached end of search space")
        return None


def parse_hex_int(value):
    """Parse a hex string to an integer, supporting '0x' prefix."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        if value.lower().startswith('0x'):
            return int(value, 16)
        try:
            return int(value, 16)
        except ValueError:
            try:
                return int(value)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Cannot parse '{value}' as hex or decimal integer")
    raise argparse.ArgumentTypeError(f"Cannot parse '{value}' as hex or decimal integer")


def main():
    """Main entry point with command line argument parsing."""
    parser = argparse.ArgumentParser(description="ECDSA Nonce Recovery Tool")
    parser.add_argument("--r", type=str, required=True, help="r component of signature (hex)")
    parser.add_argument("--s", type=str, required=True, help="s component of signature (hex)")
    parser.add_argument("--z", type=str, required=True, help="Message hash (hex)")
    parser.add_argument("--start", type=str, default="1", help="Starting value for brute force (hex or decimal)")
    parser.add_argument("--parallel", action="store_true", help="Use parallel processing")
    parser.add_argument("--processes", type=int, default=16, help="Number of processes to use (default: 16)")
    parser.add_argument("--chunk-size", type=int, default=1000, help="Chunk size for parallel processing")
    parser.add_argument("--checkpoint-interval", type=int, default=1000, help="How often to save progress")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Parse hex values
    r = parse_hex_int(args.r)
    s = parse_hex_int(args.s)
    z = parse_hex_int(args.z)
    k_start = parse_hex_int(args.start)
    
    try:
        # Create tool and run recovery
        tool = NonceRecoveryTool(r, s, z, k_start)
        result = tool.recover(
            use_multiprocessing=args.parallel,
            num_processes=args.processes,
            chunk_size=args.chunk_size
        )
        
        if result:
            logger.info(f"{'=' * 80}")
            logger.info(f"Recovery successful! Nonce: 0x{result:x}")
            logger.info(f"{'=' * 80}")
            return 0
        else:
            logger.error("Failed to recover nonce")
            return 1
    
    except Exception as e:
        logger.exception(f"Error during nonce recovery: {e}")
        return 1


if __name__ == "__main__":
    # Example usage with proper hex values
    if len(sys.argv) == 1:
        # If no args provided, use example values
        print("\nECDSA NONCE RECOVERY TOOL v4.0 - Example Mode")
        print("=" * 50)
        print("Running with example values. For real use, provide command line arguments.")
        print("See --help for options.\n")
        
        # Example values
        r = 0x00e1de2aea5f0b8e2d97f244b5a4e14e6752d88ca46d8821777e9
        s = 0x1dd566fb377bd782af7de11dad9ff552746eeeadcde
        z = 0xabfe106fb5873c5419cf2265da1c5f02d1aa77c4f
        k_start = 1000000000000000000000
        
        try:
            # Create tool and run recovery
            tool = NonceRecoveryTool(r, s, z, k_start)
            result = tool.recover(use_multiprocessing=True, chunk_size=100)
            
            if result:
                print(f"\nSuccess! Nonce recovered: 0x{result:x}")
            else:
                print("\nFailed to recover nonce")
        except Exception as e:
            print(f"\nError: {e}")
    else:
        # Otherwise, use command line arguments
        sys.exit(main())

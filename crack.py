#!/usr/bin/env python3
import hashlib
import itertools
import string
import time
import re
import sys
import numpy as np
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
import ctypes

# GPU acceleration imports
try:
    import cupy as cp
    # Check for a valid GPU device
    if cp.cuda.runtime.getDeviceCount() > 0:
        GPU_AVAILABLE = True
        GPU_TYPE = "CuPy"
        print("GPU acceleration enabled (CuPy)")
    else:
        GPU_AVAILABLE = False
        GPU_TYPE = None
        print("CuPy found, but no compatible GPU detected - using CPU with multiprocessing")
except ImportError:
    GPU_AVAILABLE = False
    GPU_TYPE = None
    print("CuPy not found - GPU acceleration not available - using CPU with multiprocessing")

# Target Configuration
TARGET_HASH = "PUT YOUR SHA1 HASH HERE" # Hash to decrypt - change this value to target a different hash
TARGET_PREFIX = "PUT YOUR PASSOWRD WHAT YOU KNEW HALF OF IT" # Target prefix - only put the showed password prefix here dont put the * on

# Analysis Parameters
MAX_SEARCH_SPACE = 100000000000  # Increased for longer passwords
PROGRESS_UPDATE_FREQUENCY = 10000
BATCH_SIZE = 100000  # Process batches for better performance
GPU_BATCH_SIZE = 40000000  # Larger batches for GPU processing (e.g., 40 million)
NUM_WORKERS = mp.cpu_count()  # Use all available CPU cores

# Global atomic flag for early stopping
stop_flag = mp.Value(ctypes.c_bool, False)

# --- NEW: CUDA C++ Kernel for SHA-1 Hashing ---
# This kernel is compiled by CuPy at runtime. Each GPU thread runs this code in parallel.
sha1_kernel_code = r'''
extern "C" {
    // Device function to rotate left
    __device__ unsigned int rotl(unsigned int value, unsigned int shift) {
        return (value << shift) | (value >> (32 - shift));
    }

    // Main SHA-1 transformation function for a single 64-byte block
    __device__ void sha1_transform(unsigned int state[5], const unsigned char block[64]) {
        unsigned int w[80];

        // Copy block to word array and convert to big-endian
        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        // Extend the 16 words into 80 words
        for (int i = 16; i < 80; ++i) {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        unsigned int a = state[0];
        unsigned int b = state[1];
        unsigned int c = state[2];
        unsigned int d = state[3];
        unsigned int e = state[4];

        // Main loop
        for (int i = 0; i < 80; ++i) {
            unsigned int f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            unsigned int temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
    }

    // The main kernel launched from Python
    __global__ void sha1_cracker(const unsigned char* candidates, const int* lengths, int num_candidates, const unsigned int* target_hash, int* result_index) {
        int idx = blockIdx.x * blockDim.x + threadIdx.x;
        if (idx >= num_candidates) {
            return;
        }
        
        // If a result is already found by another thread, stop.
        if (result_index[0] != -1) {
            return;
        }

        // SHA-1 state initialization
        unsigned int state[5];
        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
        state[4] = 0xC3D2E1F0;
        
        unsigned char block[64];
        int len = lengths[idx];
        int offset = idx * 64; // Max length is 64, matches padding block size

        // Manual padding (PKCS#7) for a single block
        for(int i = 0; i < len; ++i) {
            block[i] = candidates[offset + i];
        }
        block[len] = 0x80; // Start of padding
        for(int i = len + 1; i < 56; ++i) {
            block[i] = 0; // Zero padding
        }
        
        // Append original length in bits (big-endian)
        unsigned long long bit_len = len * 8;
        block[63] = bit_len & 0xFF;
        block[62] = (bit_len >> 8) & 0xFF;
        block[61] = (bit_len >> 16) & 0xFF;
        block[60] = (bit_len >> 24) & 0xFF;
        block[59] = (bit_len >> 32) & 0xFF;
        block[58] = (bit_len >> 40) & 0xFF;
        block[57] = (bit_len >> 48) & 0xFF;
        block[56] = (bit_len >> 56) & 0xFF;

        // Perform the transformation
        sha1_transform(state, block);

        // Check if the computed hash matches the target
        if (state[0] == target_hash[0] && state[1] == target_hash[1] && state[2] == target_hash[2] && state[3] == target_hash[3] && state[4] == target_hash[4]) {
            // Atomically write the index of the found password.
            atomicExch(&result_index[0], idx);
        }
    }
}
'''

# --- Global CuPy Kernel Cache ---
# Compiling the kernel is slow, so we do it once and cache it.
_cupy_kernel_cache = None

def get_cupy_sha1_kernel():
    """Lazily compiles and caches the CuPy SHA-1 kernel."""
    global _cupy_kernel_cache
    if _cupy_kernel_cache is None:
        print("Compiling CUDA kernel for GPU... (this happens only once)")
        # We use RawKernel to compile our custom C++ code. [1, 2]
        _cupy_kernel_cache = cp.RawKernel(sha1_kernel_code, 'sha1_cracker')
        print("Kernel compiled successfully.")
    return _cupy_kernel_cache

@dataclass
class AttackVector:
    """Data structure representing a single attack configuration"""
    prefix: str
    suffix_length: int
    charset: str
    priority: int = 1
    mask_pattern: Optional[str] = None  # e.g., "????1234" for fixed positions

@dataclass
class MaskPattern:
    """Mask-based attack pattern for surgical cracking"""
    pattern: str  # e.g., "?l?l?d?d" where ?l=lowercase, ?d=digit
    charset_map: Dict[str, str] = None
    
    def __post_init__(self):
        if self.charset_map is None:
            self.charset_map = {
                '?l': string.ascii_lowercase,
                '?u': string.ascii_uppercase,
                '?d': string.digits,
                '?s': "!@#$%^&*()_+-=[]{}|;:,.<>?",
                '?a': string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
            }

class OptimizedCandidateGenerator:
    """Memory-efficient candidate generator using bytearray buffers"""
    
    def __init__(self, prefix: str, suffix_length: int, charset: str):
        self.prefix = prefix.encode('utf-8')
        self.suffix_length = suffix_length
        self.charset = charset.encode('utf-8')
        self.buffer = bytearray(len(self.prefix) + suffix_length)
        self.buffer[:len(self.prefix)] = self.prefix
        
    def generate_batch(self, start_index: int, batch_size: int) -> List[bytes]:
        """Generate a batch of candidates as bytes objects"""
        candidates = []
        charset_len = len(self.charset)
        
        for i in range(batch_size):
            current_index = start_index + i
            if current_index >= charset_len ** self.suffix_length:
                break
                
            temp_index = current_index
            for pos in range(self.suffix_length - 1, -1, -1):
                char_index = temp_index % charset_len
                self.buffer[len(self.prefix) + pos] = self.charset[char_index]
                temp_index //= charset_len
                
            candidates.append(bytes(self.buffer))
            
        return candidates

def hash_batch_cpu_optimized(candidates_batch: List[bytes], target_hash_bytes: bytes, stop_flag) -> Optional[str]:
    """Optimized CPU batch processing with early stopping"""
    for candidate_bytes in candidates_batch:
        if stop_flag.value:
            return None
        if hashlib.sha1(candidate_bytes).digest() == target_hash_bytes:
            return candidate_bytes.decode('utf-8')
    return None

def hash_batch_gpu_cupy(candidates_batch: List[bytes], target_hash: str, stop_flag) -> Optional[str]:
    """
    True GPU SHA-1 batch processing using a custom CuPy RawKernel. [1, 2]
    This function now orchestrates the GPU cracking process.
    """
    if stop_flag.value:
        return None

    kernel = get_cupy_sha1_kernel()
    
    batch_size = len(candidates_batch)
    # The kernel assumes a max password length of 64 bytes for simplicity.
    max_len = 64 

    # Prepare data for the GPU
    lengths = np.array([len(c) for c in candidates_batch], dtype=np.int32)
    
    # Flatten candidates into a single large byte array
    candidates_flat = b''.join(c.ljust(max_len, b'\0') for c in candidates_batch)
    
    # Convert hex target hash to an array of 5 unsigned integers (the SHA-1 state)
    target_hash_uint32 = np.frombuffer(bytes.fromhex(target_hash), dtype='>u4')
    
    # --- Transfer data to GPU memory ---
    d_candidates = cp.array(np.frombuffer(candidates_flat, dtype=np.uint8))
    d_lengths = cp.array(lengths)
    d_target_hash = cp.array(target_hash_uint32)
    d_result_index = cp.full(1, -1, dtype=cp.int32) # -1 means not found

    # --- Kernel Launch Configuration ---
    threads_per_block = 256
    blocks_per_grid = (batch_size + threads_per_block - 1) // threads_per_block
    
    # --- Execute the kernel on the GPU ---
    # The kernel is called with grid size, block size, and its arguments. [2, 4]
    kernel((blocks_per_grid,), (threads_per_block,), (
        d_candidates, d_lengths, batch_size, d_target_hash, d_result_index
    ))
    
    # --- Retrieve result from GPU ---
    result_index = d_result_index.get()[0] # .get() copies data from GPU to CPU
    
    if result_index != -1:
        # Password was found in this batch
        found_password_bytes = candidates_batch[result_index]
        return found_password_bytes.decode('utf-8')
        
    return None

def process_cpu_worker(args):
    """Worker function for ProcessPoolExecutor"""
    candidates_batch, target_hash, worker_id = args
    target_hash_bytes = bytes.fromhex(target_hash)
    
    for candidate in candidates_batch:
        if stop_flag.value:
            return None
        if hashlib.sha1(candidate).digest() == target_hash_bytes:
            stop_flag.value = True
            return candidate.decode('utf-8')
    return None

class CryptographicAnalyzer:
    def __init__(self, target_hash: str):
        self.target_hash = self._normalize_hash(target_hash)

    def _normalize_hash(self, hash_value: str) -> str:
        normalized = hash_value.strip().lower()
        if not self._validate_sha1_format(normalized):
            raise ValueError(f"Invalid SHA-1 hash format: {hash_value}")
        return normalized

    def _validate_sha1_format(self, hash_string: str) -> bool:
        return bool(re.match(r'^[a-f0-9]{40}$', hash_string))

    def _compute_sha1(self, plaintext: str) -> str:
        return hashlib.sha1(plaintext.encode('utf-8')).hexdigest()

    def _calculate_search_complexity(self, charset_size: int, length: int) -> int:
        return charset_size ** length

    def _generate_progress_report(self, current: int, total: int, start_time: float) -> str:
        elapsed = time.time() - start_time
        percentage = (current / total) * 100
        rate = current / elapsed if elapsed > 0 else 0

        eta_formatted = "calculating..."
        if rate > 0 and current < total:
            eta = (total - current) / rate
            if eta < 60:
                eta_formatted = f"{eta:.1f}s"
            elif eta < 3600:
                eta_formatted = f"{eta/60:.1f}m"
            else:
                eta_formatted = f"{eta/3600:.1f}h"

        return (f"Progress: {current:,}/{total:,} ({percentage:.2f}%) | "
                f"Rate: {rate:,.0f} ops/sec | ETA: {eta_formatted}")

    def execute_suffix_analysis(self, prefix: str, suffix_length: int, charset: str, mask_pattern: Optional[str] = None) -> Optional[str]:
        search_space = self._calculate_search_complexity(len(charset), suffix_length)

        print(f"Initiating suffix analysis: prefix='{prefix}', length={suffix_length}")
        print(f"Search space complexity: {search_space:,} combinations")

        acceleration_type = f"GPU ({GPU_TYPE})" if GPU_AVAILABLE else f"CPU ({NUM_WORKERS} cores)"
        print(f"Using {acceleration_type} acceleration")

        if search_space > MAX_SEARCH_SPACE:
            print(f"Complexity exceeds threshold, skipping...")
            return None

        stop_flag.value = False
        analysis_start = time.time()

        if GPU_AVAILABLE:
            return self._execute_gpu_cupy_analysis(prefix, suffix_length, charset,
                                                 search_space, analysis_start)
        else:
            return self._execute_optimized_cpu_analysis(prefix, suffix_length, charset,
                                                      search_space, analysis_start)

    def _execute_gpu_cupy_analysis(self, prefix: str, suffix_length: int, charset: str,
                                  search_space: int, analysis_start: float) -> Optional[str]:
        """GPU-accelerated analysis using our custom CuPy kernel."""
        batch_size = GPU_BATCH_SIZE
        generator = OptimizedCandidateGenerator(prefix, suffix_length, charset)
        
        for batch_start in range(0, search_space, batch_size):
            if stop_flag.value:
                break
                
            current_batch_size = min(batch_size, search_space - batch_start)
            
            # Generate batch of candidates as bytes
            candidate_bytes_list = generator.generate_batch(batch_start, current_batch_size)
            
            if not candidate_bytes_list:
                break
                
            result = hash_batch_gpu_cupy(candidate_bytes_list, self.target_hash, stop_flag)
            if result:
                stop_flag.value = True
                return result
            
            # Progress reporting
            current_progress = min(batch_start + current_batch_size, search_space)
            progress_report = self._generate_progress_report(current_progress, search_space, analysis_start)
            print(f"\r{progress_report}", end="")
        
        print() # Newline after progress bar
        return None

    def _execute_optimized_cpu_analysis(self, prefix: str, suffix_length: int, charset: str,
                                      search_space: int, analysis_start: float) -> Optional[str]:
        """Optimized CPU analysis using ProcessPoolExecutor."""
        batch_size = BATCH_SIZE
        generator = OptimizedCandidateGenerator(prefix, suffix_length, charset)

        with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
            futures = {}
            for batch_start in range(0, search_space, batch_size):
                if stop_flag.value:
                    break
                
                current_batch_size = min(batch_size, search_space - batch_start)
                candidate_bytes_list = generator.generate_batch(batch_start, current_batch_size)
                
                if not candidate_bytes_list:
                    break
                
                future = executor.submit(process_cpu_worker, (candidate_bytes_list, self.target_hash, len(futures)))
                futures[future] = batch_start + current_batch_size

                # Process completed futures
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        stop_flag.value = True
                        # Cancel remaining futures
                        for future_to_cancel in futures:
                            future_to_cancel.cancel()
                        return result

                    # Update progress and remove completed future
                    current_progress = futures.pop(f)
                    progress_report = self._generate_progress_report(current_progress, search_space, analysis_start)
                    print(f"\r{progress_report}", end="")
                    break # Only process one completed future at a time to keep submitting new tasks
        
        print() # Newline after progress bar
        return None

    def execute_mask_attack(self, mask_pattern: MaskPattern) -> Optional[str]:
        """Execute mask-based attack for surgical password cracking"""
        print(f"Executing mask attack with pattern: {mask_pattern.pattern}")
        
        positions = []
        fixed_chars = list(mask_pattern.pattern)
        
        i = 0
        while i < len(mask_pattern.pattern):
            if mask_pattern.pattern[i] == '?' and i + 1 < len(mask_pattern.pattern):
                mask_char = '?' + mask_pattern.pattern[i + 1]
                if mask_char in mask_pattern.charset_map:
                    positions.append(mask_pattern.charset_map[mask_char])
                    fixed_chars[i] = None
                    fixed_chars[i+1] = None
                    i += 2
                else:
                    i += 1
            else:
                i += 1
        
        search_space = 1
        for charset in positions:
            search_space *= len(charset)
        
        print(f"Mask search space: {search_space:,} combinations")
        if search_space > MAX_SEARCH_SPACE:
            print("Mask complexity exceeds threshold, skipping...")
            return None

        # This part remains on the CPU as it's often small and complex to vectorize
        base_candidate = [c for c in fixed_chars if c is not None]
        var_indices = [i for i, c in enumerate(fixed_chars) if c is None and (i == 0 or fixed_chars[i-1] is not None)]

        analysis_start = time.time()
        count = 0
        target_hash_bytes = bytes.fromhex(self.target_hash)

        for combination in itertools.product(*positions):
            if stop_flag.value: break
            
            candidate_list = list(base_candidate)
            for i, char in enumerate(combination):
                candidate_list.insert(var_indices[i], char)
            
            candidate_str = "".join(candidate_list)
            
            if hashlib.sha1(candidate_str.encode('utf-8')).digest() == target_hash_bytes:
                return candidate_str
            
            count +=1
            if count % 100000 == 0:
                progress_report = self._generate_progress_report(count, search_space, analysis_start)
                print(f"\r{progress_report}", end="")

        print()
        return None

    def generate_attack_vectors(self, prefix: str) -> List[AttackVector]:
        # Return vectors sorted by priority, then by complexity (smaller search spaces first)
        vectors = [
            AttackVector(prefix, 4, string.ascii_lowercase, priority=1),
            AttackVector(prefix, 3, string.ascii_lowercase + string.digits, priority=1),
            AttackVector(prefix, 4, string.ascii_lowercase + string.digits, priority=1),
            AttackVector(prefix, 2, string.ascii_lowercase + string.digits, priority=1),
            AttackVector(prefix, 1, string.ascii_lowercase + string.digits, priority=1),
            AttackVector(prefix, 5, string.ascii_lowercase, priority=2),
            AttackVector(prefix, 4, string.ascii_letters, priority=2),
            AttackVector(prefix, 5, string.digits, priority=2),
            AttackVector(prefix, 6, string.digits, priority=2),
            AttackVector(prefix, 3, string.ascii_letters + string.digits, priority=2),
            AttackVector(prefix, 4, string.ascii_letters + string.digits + "!@#$%", priority=3),
            AttackVector(prefix, 5, string.ascii_lowercase + string.digits, priority=3),
            AttackVector(prefix, 6, string.ascii_lowercase, priority=3),
            AttackVector(prefix, 5, string.ascii_letters, priority=3),
            AttackVector(prefix, 7, string.digits, priority=3),
            AttackVector(prefix, 8, string.digits, priority=3),
            AttackVector(prefix, 6, string.ascii_lowercase + string.digits, priority=4),
            AttackVector(prefix, 7, string.ascii_lowercase, priority=4),
            AttackVector(prefix, 5, string.ascii_letters + string.digits, priority=4),
            AttackVector(prefix, 9, string.digits, priority=4),
            AttackVector(prefix, 10, string.digits, priority=4),
            AttackVector(prefix, 8, string.ascii_lowercase, priority=5),
            AttackVector(prefix, 7, string.ascii_lowercase + string.digits, priority=5),
            AttackVector(prefix, 6, string.ascii_letters, priority=5),
            AttackVector(prefix, 11, string.digits, priority=5),
            AttackVector(prefix, 12, string.digits, priority=5),
            AttackVector(prefix, 9, string.ascii_lowercase, priority=6),
            AttackVector(prefix, 8, string.ascii_lowercase + string.digits, priority=6),
            AttackVector(prefix, 7, string.ascii_letters, priority=6),
            AttackVector(prefix, 10, string.ascii_lowercase, priority=7),
            AttackVector(prefix, 9, string.ascii_lowercase + string.digits, priority=7),
            AttackVector(prefix, 8, string.ascii_letters, priority=7),
        ]
        
        # Sort by priority, then by search space size to tackle easier tasks first
        vectors.sort(key=lambda v: (v.priority, len(v.charset)**v.suffix_length))
        return vectors

class SecurityAnalysisEngine:
    def __init__(self):
        self.analyzer = None
        self.analysis_session_start = None

    def validate_configuration(self) -> bool:
        try:
            CryptographicAnalyzer(TARGET_HASH)
            if not TARGET_PREFIX:
                print("Configuration Warning: Target prefix is empty.")
            if MAX_SEARCH_SPACE < 1:
                print("Configuration Error: Maximum search space must be positive")
                return False
            return True
        except ValueError as e:
            print(f"Configuration Error: {e}")
            return False

    def execute_comprehensive_analysis(self) -> Optional[str]:
        print("=" * 70)
        print("SHA-1 CRYPTOGRAPHIC ANALYSIS ENGINE - GPU OPTIMIZED")
        print("=" * 70)
        print(f"Target Hash: {TARGET_HASH}")
        print(f"Analysis Prefix: {TARGET_PREFIX}")
        print(f"Maximum Search Space: {MAX_SEARCH_SPACE:,} combinations")

        acceleration_type = f"GPU ({GPU_TYPE})" if GPU_AVAILABLE else f"CPU ({NUM_WORKERS} cores)"
        print(f"Acceleration: {acceleration_type}")
        
        optimizations = []
        if GPU_AVAILABLE:
            optimizations.append("Custom CUDA C++ SHA-1 kernel")
            optimizations.append("Cached kernel compilation")
            optimizations.append(f"GPU batch size: {GPU_BATCH_SIZE:,}")
        else:
             optimizations.append("ProcessPool for CPU parallelism")
             optimizations.append(f"CPU batch size: {BATCH_SIZE:,}")

        optimizations.extend([
            "Memory-efficient candidate generation",
            "Early stopping with atomic flags",
            "Accurate progress tracking"
        ])
        print(f"Optimizations: {', '.join(optimizations)}")
        print("=" * 70)

        self.analyzer = CryptographicAnalyzer(TARGET_HASH)
        self.analysis_session_start = time.time()
        
        attack_vectors = self.analyzer.generate_attack_vectors(TARGET_PREFIX)

        for vector_index, vector in enumerate(attack_vectors, 1):
            if stop_flag.value:
                print("\nAnalysis stopped by early termination flag.")
                break
                
            complexity = len(vector.charset) ** vector.suffix_length
            print(f"\n--- Vector {vector_index}/{len(attack_vectors)} [Priority: {vector.priority}] ---")
            print(f"Pattern: {vector.prefix} + {vector.suffix_length} chars from a set of {len(vector.charset)}")
            print(f"Computational complexity: {complexity:,}")

            if complexity > MAX_SEARCH_SPACE:
                print("Complexity exceeds threshold, skipping...")
                continue

            vector_start = time.time()
            result = self.analyzer.execute_suffix_analysis(
                vector.prefix, vector.suffix_length, vector.charset
            )
            vector_duration = time.time() - vector_start

            if result:
                return self._generate_success_report(result, vector_duration)
            
            if not stop_flag.value:
                 print(f"Vector completed without success in {vector_duration:.1f}s")

        return self._generate_failure_report()

    def _generate_success_report(self, recovered_plaintext: str, analysis_duration: float) -> str:
        total_duration = time.time() - self.analysis_session_start
        print("\n" + "="*70)
        print("PASSWORD FOUND!")
        print(f"Recovered Plaintext: {recovered_plaintext}")
        print(f"Time to Crack Vector: {analysis_duration:.2f} seconds")
        print(f"Total Analysis Time: {total_duration:.2f} seconds")

        verification_hash = hashlib.sha1(recovered_plaintext.encode()).hexdigest()
        print("\n--- Verification ---")
        print(f"  Target Hash: {TARGET_HASH}")
        print(f"   Found Hash: {verification_hash}")
        print(f"        Match: {verification_hash == self.analyzer.target_hash}")
        print("="*70)
        return recovered_plaintext

    def _generate_failure_report(self) -> None:
        if stop_flag.value: return # Don't show failure if stopped early
        total_duration = time.time() - self.analysis_session_start
        print("\n" + "="*70)
        print(f"Analysis completed without successful recovery.")
        print(f"Total analysis time: {total_duration:.2f} seconds")
        print("\nPotential factors:")
        print(f"  - Password not covered by the defined charsets and lengths.")
        print(f"  - Prefix '{TARGET_PREFIX}' may be incorrect.")
        print(f"  - Consider adding more complex attack vectors or masks.")
        print("="*70)

def main():
    try:
        if sys.platform == 'win32' and hasattr(mp, 'set_start_method'):
            mp.set_start_method('spawn', force=True)
        
        engine = SecurityAnalysisEngine()

        if not engine.validate_configuration():
            sys.exit(1)

        result = engine.execute_comprehensive_analysis()

        if result:
            print(f"\nAnalysis Status: SUCCESS")
        else:
            print(f"\nAnalysis Status: UNSUCCESSFUL")

    except KeyboardInterrupt:
        print(f"\n\nAnalysis interrupted by operator.")
        stop_flag.value = True
        sys.exit(130)
    except Exception as e:
        print(f"\nCRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        stop_flag.value = True
        sys.exit(1)
    finally:
        stop_flag.value = True

if __name__ == "__main__":
    main()

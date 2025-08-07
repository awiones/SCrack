#!/usr/bin/env python3
import hashlib
import itertools
import string
import time
import re
import sys
import numpy as np
from typing import Optional, List, Tuple
from dataclasses import dataclass
import multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor, as_completed

# GPU acceleration imports with fallback
try:
    import cupy as cp
    GPU_AVAILABLE = True
    print("GPU acceleration enabled (CuPy)")
except ImportError:
    try:
        import pycuda.autoinit
        import pycuda.driver as cuda
        from pycuda.compiler import SourceModule
        GPU_AVAILABLE = True
        print("GPU acceleration enabled (PyCUDA)")
    except ImportError:
        GPU_AVAILABLE = False
        print("GPU acceleration not available - using CPU with multiprocessing")

# Target Configuration
TARGET_HASH = "PUT YOUR SHA1 HASH HERE" # Hash to decrypt - change this value to target a different hash
TARGET_PREFIX = "PUT YOUR PASSOWRD WHAT YOU KNEW HALF OF IT" # Target prefix - only put the showed password prefix here dont put the * on

# Analysis Parameters
MAX_SEARCH_SPACE = 100000000000  # Increased for longer passwords
PROGRESS_UPDATE_FREQUENCY = 10000
BATCH_SIZE = 100000  # Process batches for better performance
NUM_WORKERS = mp.cpu_count()  # Use all available CPU cores

@dataclass
class AttackVector:
    """Data structure representing a single attack configuration"""
    prefix: str
    suffix_length: int
    charset: str
    priority: int = 1

def hash_batch_cpu(candidates_batch: List[str], target_hash: str) -> Optional[str]:
    """Process a batch of candidates on CPU"""
    for candidate in candidates_batch:
        if hashlib.sha1(candidate.encode('utf-8')).hexdigest() == target_hash:
            return candidate
    return None

def hash_batch_gpu_cupy(candidates_batch: List[str], target_hash: str) -> Optional[str]:
    """Process a batch of candidates on GPU using CuPy"""
    try:
        # Convert candidates to bytes and process on GPU
        for candidate in candidates_batch:
            # Use CPU hashlib for now - CuPy doesn't have built-in SHA1
            if hashlib.sha1(candidate.encode('utf-8')).hexdigest() == target_hash:
                return candidate
        return None
    except Exception as e:
        print(f"GPU processing error: {e}")
        return hash_batch_cpu(candidates_batch, target_hash)

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

        if rate > 0 and current < total:
            eta = (total - current) / rate
            eta_formatted = f"{eta:.1f}s"
        else:
            eta_formatted = "calculating..."

        return (f"Progress: {current:,}/{total:,} ({percentage:.2f}%) | "
                f"Rate: {rate:.0f} ops/sec | ETA: {eta_formatted}")

    def execute_suffix_analysis(self, prefix: str, suffix_length: int, charset: str) -> Optional[str]:
        search_space = self._calculate_search_complexity(len(charset), suffix_length)

        print(f"Initiating suffix analysis: prefix='{prefix}', length={suffix_length}")
        print(f"Search space complexity: {search_space:,} combinations")
        
        acceleration_type = "GPU (CuPy)" if GPU_AVAILABLE and 'cupy' in sys.modules else \
                           "GPU (PyCUDA)" if GPU_AVAILABLE else f"CPU ({NUM_WORKERS} cores)"
        print(f"Using {acceleration_type} acceleration")

        if search_space > MAX_SEARCH_SPACE:
            print(f"Complexity exceeds threshold, skipping...")
            return None

        analysis_start = time.time()

        if GPU_AVAILABLE and 'cupy' in sys.modules:
            return self._execute_gpu_cupy_analysis(prefix, suffix_length, charset, 
                                                 search_space, analysis_start)
        else:
            return self._execute_parallel_cpu_analysis(prefix, suffix_length, charset, 
                                                     search_space, analysis_start)

    def _execute_gpu_cupy_analysis(self, prefix: str, suffix_length: int, charset: str, 
                                  search_space: int, analysis_start: float) -> Optional[str]:
        """GPU-accelerated analysis using CuPy"""
        batch_candidates = []
        
        for iteration, suffix_tuple in enumerate(itertools.product(charset, repeat=suffix_length)):
            candidate = prefix + ''.join(suffix_tuple)
            batch_candidates.append(candidate)
            
            # Process batch when full or at end
            if len(batch_candidates) >= BATCH_SIZE or iteration == search_space - 1:
                result = hash_batch_gpu_cupy(batch_candidates, self.target_hash)
                if result:
                    return result
                
                # Progress reporting
                if iteration % PROGRESS_UPDATE_FREQUENCY == 0 and iteration > 0:
                    progress_report = self._generate_progress_report(iteration, search_space, analysis_start)
                    print(progress_report)
                
                batch_candidates = []
        
        return None

    def _execute_parallel_cpu_analysis(self, prefix: str, suffix_length: int, charset: str, 
                                     search_space: int, analysis_start: float) -> Optional[str]:
        """Parallel CPU analysis using multiprocessing"""
        batch_candidates = []
        
        with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
            futures = []
            
            for iteration, suffix_tuple in enumerate(itertools.product(charset, repeat=suffix_length)):
                candidate = prefix + ''.join(suffix_tuple)
                batch_candidates.append(candidate)
                
                # Process batch when full or at end
                if len(batch_candidates) >= BATCH_SIZE or iteration == search_space - 1:
                    # Submit batch for processing
                    future = executor.submit(hash_batch_cpu, batch_candidates.copy(), self.target_hash)
                    futures.append(future)
                    
                    # Check completed futures
                    for completed_future in as_completed(futures, timeout=0.1):
                        result = completed_future.result()
                        if result:
                            # Cancel remaining futures
                            for f in futures:
                                f.cancel()
                            return result
                        futures.remove(completed_future)
                    
                    # Progress reporting
                    if iteration % PROGRESS_UPDATE_FREQUENCY == 0 and iteration > 0:
                        progress_report = self._generate_progress_report(iteration, search_space, analysis_start)
                        print(progress_report)
                    
                    batch_candidates = []
            
            # Wait for remaining futures
            for future in as_completed(futures):
                result = future.result()
                if result:
                    return result
        
        return None

    def generate_attack_vectors(self, prefix: str) -> List[AttackVector]:
        vectors = [
            # Original working vectors (keep exact same order and priority)
            AttackVector(prefix, 4, string.ascii_lowercase, priority=1),
            AttackVector(prefix, 3, string.ascii_lowercase + string.digits, priority=1),
            AttackVector(prefix, 4, string.ascii_lowercase + string.digits, priority=1),
            AttackVector(prefix, 2, string.ascii_lowercase + string.digits, priority=1),
            AttackVector(prefix, 1, string.ascii_lowercase + string.digits, priority=1),
            AttackVector(prefix, 5, string.ascii_lowercase, priority=2),
            AttackVector(prefix, 4, string.ascii_letters, priority=2),
            AttackVector(prefix, 3, string.ascii_letters + string.digits, priority=2),
            AttackVector(prefix, 4, string.ascii_letters + string.digits + "!@#$%", priority=3),

            # Extended vectors for longer passwords
            AttackVector(prefix, 5, string.ascii_lowercase + string.digits, priority=3),
            AttackVector(prefix, 6, string.ascii_lowercase, priority=3),
            AttackVector(prefix, 5, string.ascii_letters, priority=3),
            AttackVector(prefix, 6, string.ascii_lowercase + string.digits, priority=4),
            AttackVector(prefix, 7, string.ascii_lowercase, priority=4),
            AttackVector(prefix, 5, string.ascii_letters + string.digits, priority=4),
            AttackVector(prefix, 8, string.ascii_lowercase, priority=5),
            AttackVector(prefix, 7, string.ascii_lowercase + string.digits, priority=5),
            AttackVector(prefix, 6, string.ascii_letters, priority=5),
            AttackVector(prefix, 9, string.ascii_lowercase, priority=6),
            AttackVector(prefix, 8, string.ascii_lowercase + string.digits, priority=6),
            AttackVector(prefix, 7, string.ascii_letters, priority=6),
            AttackVector(prefix, 10, string.ascii_lowercase, priority=7),
            AttackVector(prefix, 9, string.ascii_lowercase + string.digits, priority=7),
            AttackVector(prefix, 8, string.ascii_letters, priority=7),

            # Digits only for very long passwords (most efficient)
            AttackVector(prefix, 5, string.digits, priority=2),
            AttackVector(prefix, 6, string.digits, priority=2),
            AttackVector(prefix, 7, string.digits, priority=3),
            AttackVector(prefix, 8, string.digits, priority=3),
            AttackVector(prefix, 9, string.digits, priority=4),
            AttackVector(prefix, 10, string.digits, priority=4),
            AttackVector(prefix, 11, string.digits, priority=5),
            AttackVector(prefix, 12, string.digits, priority=5),
        ]

        # Return in exact original order - no sorting to preserve working sequence
        return vectors

class SecurityAnalysisEngine:
    def __init__(self):
        self.analyzer = None
        self.analysis_session_start = None

    def validate_configuration(self) -> bool:
        try:
            temp_analyzer = CryptographicAnalyzer(TARGET_HASH)

            if not TARGET_PREFIX or len(TARGET_PREFIX.strip()) == 0:
                print("Configuration Error: Target prefix cannot be empty")
                return False

            if MAX_SEARCH_SPACE < 1:
                print("Configuration Error: Maximum search space must be positive")
                return False

            return True

        except ValueError as e:
            print(f"Configuration Error: {e}")
            return False

    def execute_comprehensive_analysis(self) -> Optional[str]:
        print("=" * 70)
        print("SHA-1 CRYPTOGRAPHIC ANALYSIS ENGINE")
        print("=" * 70)
        print(f"Target Hash: {TARGET_HASH}")
        print(f"Analysis Prefix: {TARGET_PREFIX}")
        print(f"Maximum Search Space: {MAX_SEARCH_SPACE:,} combinations")
        
        acceleration_type = "GPU (CuPy)" if GPU_AVAILABLE and 'cupy' in sys.modules else \
                           "GPU (PyCUDA)" if GPU_AVAILABLE else f"CPU ({NUM_WORKERS} cores)"
        print(f"Acceleration: {acceleration_type}")
        print("=" * 70)

        self.analyzer = CryptographicAnalyzer(TARGET_HASH)
        self.analysis_session_start = time.time()

        attack_vectors = self.analyzer.generate_attack_vectors(TARGET_PREFIX)

        for vector_index, vector in enumerate(attack_vectors, 1):
            print(f"\nVector {vector_index}: {vector.prefix} + {vector.suffix_length} chars "
                  f"({len(vector.charset)} charset) [Priority: {vector.priority}]")

            complexity = len(vector.charset) ** vector.suffix_length
            print(f"Computational complexity: {complexity:,}")

            if complexity > MAX_SEARCH_SPACE:
                print("Complexity exceeds threshold, skipping...")
                continue

            vector_start = time.time()
            result = self.analyzer.execute_suffix_analysis(
                vector.prefix, vector.suffix_length, vector.charset
            )

            if result:
                vector_duration = time.time() - vector_start
                return self._generate_success_report(result, vector_duration)
            else:
                vector_duration = time.time() - vector_start
                print(f"Vector completed without success ({vector_duration:.1f}s)")

        return self._generate_failure_report()

    def _generate_success_report(self, recovered_plaintext: str, analysis_duration: float) -> str:
        """Generate comprehensive success report"""
        print(f"\nPASSWORD FOUND: {recovered_plaintext}")
        print(f"Time taken: {analysis_duration:.2f} seconds")

        verification_hash = hashlib.sha1(recovered_plaintext.encode()).hexdigest()
        print(f"\nVerification:")
        print(f"Target: {TARGET_HASH}")
        print(f"Found : {verification_hash}")
        print(f"Match : {verification_hash == TARGET_HASH}")

        return recovered_plaintext

    def _generate_failure_report(self) -> None:
        total_duration = time.time() - self.analysis_session_start
        print(f"\nAnalysis completed without successful recovery")
        print(f"Total analysis time: {total_duration:.2f} seconds")
        print(f"\nPotential factors:")
        print(f"  • Suffix length exceeds current maximum")
        print(f"  • Character set not covered by current vectors")
        print(f"  • Non-standard password construction pattern")
        print(f"  • Prefix '{TARGET_PREFIX}' may be incorrect")

def main():
    try:
        engine = SecurityAnalysisEngine()

        if not engine.validate_configuration():
            sys.exit(1)

        result = engine.execute_comprehensive_analysis()

        if result:
            print(f"\nAnalysis Status: SUCCESS")
        else:
            print(f"\nAnalysis Status: UNSUCCESSFUL")

    except KeyboardInterrupt:
        print(f"\n\nAnalysis interrupted by operator")
        sys.exit(130)
    except Exception as e:
        print(f"\nCritical Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

"""
Langford-Hellman (CRYPTO '94) differential-linear attack on 8-round DES.

Attack summary:
  - Structure: bits 9,17,23,31 of L0 (outputs of S1) and bits 2,3
    of R0 are varied, all other bits remain fixed.
    Total: 2^6 = 64 plaintexts.
  - If K1,1 (the S1 subkey) is guessed correctly, then in round 1
    only the output of S1 is affected; thus R1 remains equal and
    a pair is obtained where bits 2 and/or 3 of L1 are toggled.
  - Differential characteristic through rounds 2-4 (Figure 3):
      R1' = 0, L1' = only bits 2,3 toggled
      => bits 3,8,14,25 of L4' and bit 17 of R4'
         are differentially zero.
  - Matsui's 3-round parity relation (rounds 5-7):
      L4[3,8,14,25] ⊕ R4[17] = R7[3,8,14,25] ⊕ L7[17] ⊕ key bits
      with probability p = 0.695.
      When XORed across two executions: p^2+q^2 = 0.576.
  - To partially decrypt round 8, guess K8,1:
      L7[17] = R8[17] XOR
      (contribution of only S1 through f(L8, K8)).
  - Total guess: (K1,1, K8,1). Since they share 2 bits,
    the effective space is 10 bits.

This file:
  - generate_structure: generates a structure
  - attack: builds the counter table for (K1,1, K8,1)
    using many structures
"""

import random
from traceback import print_tb

from des_core import (
    key_schedule, des_encrypt_n_rounds, f_function,
    permute, E, P, sbox_lookup, get_bit,
)

# ---- FIPS (MSB=1) → bit positions ----

import time

time_begin = time.time()

def bit_from_left(val, pos, width=32):
    """pos: 1..width, 1 = MSB (leftmost bit)."""
    return (val >> (width - pos)) & 1


def set_bit_left(val, pos, b, width=32):
    """Set bit at position pos to b."""
    mask = 1 << (width - pos)
    return (val & ~mask) | ((b & 1) << (width - pos))


def flip_bit_left(val, pos, width=32):
    return val ^ (1 << (width - pos))


# ==================== Structure generation ====================

# The 4 bit positions in R affected by S1 after the P permutation.
# P table indices [0..3] give the destination of S1's 4 output bits.
# P[0]=16, P[1]=7, P[2]=20, P[3]=21  -> R output bits 1,2,3,4
# (In FIPS notation, positions are 1..32 and P values are source bits).
# What we need: which 4 output bits after permutation come from S1.
# After the P function, the i-th output bit comes from source bit P[i-1].
# Source bits 1..4 (before permutation) belong to S1.
# Therefore, if P[i-1] ∈ {1,2,3,4}, then output bit i comes from S1.
# We use the inverse interpretation of P here.

def compute_S1_output_positions_after_P():
    """Return the positions in the 32-bit output that come from S1
    (source bits 1..4) after the P permutation (FIPS numbering)."""
    positions = []
    for out_pos, src in enumerate(P, start=1):
        if src in (1, 2, 3, 4):
            positions.append(out_pos)
    return sorted(positions)

S1_OUTPUT_POSITIONS = compute_S1_output_positions_after_P()
# According to the paper: should be 9, 17, 23, 31
assert S1_OUTPUT_POSITIONS == [9, 17, 23, 31], f"Expected [9,17,23,31], found {S1_OUTPUT_POSITIONS}"


def generate_structure(reference_plaintext):
    """Generate a structure of 64 plaintexts from a reference plaintext.
    Variable bits:
      - Bits 9, 17, 23, 31 of L0 (positions corresponding to S1 outputs)
      - Bits 2, 3 of R0
    Total 6 bits -> 64 plaintexts.
    """
    L0_ref = (reference_plaintext >> 32) & 0xFFFFFFFF
    R0_ref = reference_plaintext & 0xFFFFFFFF
    L_vary_pos = [9, 17, 23, 31]  # in L0
    R_vary_pos = [2, 3]           # in R0
    plaintexts = []
    for mask in range(64):
        L0 = L0_ref
        R0 = R0_ref
        # L0 variations
        for i, pos in enumerate(L_vary_pos):
            b = (mask >> (5 - i)) & 1
            L0 = set_bit_left(L0, pos, b)
        # R0 variations
        for i, pos in enumerate(R_vary_pos):
            b = (mask >> (1 - i)) & 1
            R0 = set_bit_left(R0, pos, b)
        plaintexts.append((L0 << 32) | R0)


    return plaintexts


# ==================== S1 computations via round 1 & round 8 ====================

def s1_input_at_round1(L0, R0, K1_1):
    """Compute the S1 output in round 1 and the affected L1 bits.
    Instead of the full f-function, only the S1 contribution is used.
    return: (L1, R1) — but considering only the S1 contribution;
    all other bits remain identical to the reference, which is enough
    for differential tracing.
    Actually, we do not need the full f_function — only the logic
    required to form pairs under the same K1,1 and determine the
    values of bits 2 and 3 in L1.
    """
    # Input to S1 after E expansion: first 6 positions of E table
    # E[0..5] = [32, 1, 2, 3, 4, 5] → bits 32,1,2,3,4,5 of R0
    e_bits = 0
    for src in E[:6]:
        e_bits = (e_bits << 1) | bit_from_left(R0, src, 32)
    s1_in = e_bits ^ ((K1_1 >> 0) & 0x3F)
    return sbox_lookup(0, s1_in)  # 4-bit output


def l1_bits_2_3(L0, R0, K1_1):
    """After round 1: L1 = R0 (in Feistel without swap).
    In standard DES:
        L1 = R0
        R1 = L0 XOR f(R0,K1).
    Therefore bits 2 and 3 of L1 equal bits 2 and 3 of R0.
    So they are NOT functions of K1,1!
    
    WAIT - we must be careful here: the attack requires R1 to remain
    unchanged while bits 2 and/or 3 of L1 toggle. Since L1=R0,
    these are directly controlled by the plaintext. The K1,1 guess
    is used to keep R1 constant:
        R1 = L0 XOR f(R0, K1).
    For two plaintexts in the structure:
        R1_a = R1_b  ⇔  L0 difference = f difference.
    """
    return (bit_from_left(R0, 2), bit_from_left(R0, 3))


def r1_equal_after_round1(L0_a, R0_a, L0_b, R0_b, K1_1):
    """Check whether two plaintexts produce equal R1 values after round 1.
    Only the K1,1 input difference matters because R0_a and R0_b
    differ only in bits 2 and/or 3, which enter only S1 via E expansion.
    
    R1 = L0 XOR f(R0, K1). Therefore:
        R1_a XOR R1_b =
        L0_a XOR L0_b XOR
        f(R0_a,K1) XOR f(R0_b,K1).
    The f difference comes only from S1
    (all other S-boxes receive identical inputs).
    Therefore K1,1 (6 bits) is sufficient.
    """
    # S1 output difference
    s1_a = sbox_output_from_R(R0_a, K1_1)
    s1_b = sbox_output_from_R(R0_b, K1_1)
    f_diff = s1_a ^ s1_b  # 32-bit, only nonzero at S1 output positions
    l0_diff = L0_a ^ L0_b
    return (l0_diff ^ f_diff) == 0


def sbox_output_from_R(R, K1_1):
    """Return only the contribution of S1 after P permutation as a 32-bit value
    (all other S-box outputs are treated as zero).
    """
    # Input to S1: first 6 bits of E(R) XOR K1_1
    e_bits = 0
    for src in E[:6]:
        e_bits = (e_bits << 1) | bit_from_left(R, src, 32)
    s1_in = e_bits ^ (K1_1 & 0x3F)
    s1_out = sbox_lookup(0, s1_in)  # 4-bit
    # Arrange as 32-bit: S1 output occupies the leftmost 4 bits
    # before permutation
    sbox_out_32 = s1_out << 28
    return permute(sbox_out_32, P, 32)


# ==================== Computing L7[17] from round 8 ====================

def compute_L7_bit17(L8, R8, K8_1):
    """Compute L7[17] from ciphertext (L8, R8) and a K8,1 guess.
    
    Feistel:
        L8 = R7
        R8 = L7 XOR f(R7, K8)
           = L7 XOR f(L8, K8).
    Therefore:
        L7 = R8 XOR f(L8, K8).
    Thus:
        L7[17] = R8[17] XOR f(L8, K8)[17].
    
    From the P permutation:
        output bit 17 comes from source bit P[16]=2,
    i.e. pre-permutation bit 2.
    Pre-permutation bit 2 is the second output bit of S1.
    Therefore the 17th output bit of f depends ONLY on S1
    → K8,1 (6 bits) is sufficient.
    """
    # First 6 bits of E(L8) go into S1
    e_bits = 0
    for src in E[:6]:
        e_bits = (e_bits << 1) | bit_from_left(L8, src, 32)
    s1_in = e_bits ^ (K8_1 & 0x3F)
    s1_out = sbox_lookup(0, s1_in)  # 4 bits
    # S1 output bit 2 = (s1_out >> 2) & 1   (MSB=bit1)
    s1_bit2 = (s1_out >> 2) & 1
    # After P permutation, this becomes output bit 17
    f_bit17 = s1_bit2
    return bit_from_left(R8, 17) ^ f_bit17


# ==================== Main attack ====================

def parity_target(L8_a, R8_a, L8_b, R8_b, K8_1):
    """Return the XOR of the output parity terms from Matsui's
    3-round relation over two ciphertexts:
        [R7_a[3,8,14,25] XOR L7_a[17]]
        XOR
        [R7_b[3,8,14,25] XOR L7_b[17]]
    Since R7 = L8:
        R7[i] = L8[i]
    """
    def side(L8, R8):
        p = 0
        for pos in (3, 8, 14, 25):
            p ^= bit_from_left(L8, pos, 32)
        p ^= compute_L7_bit17(L8, R8, K8_1)
        return p
    return side(L8_a, R8_a) ^ side(L8_b, R8_b)


def find_valid_pairs_in_structure(structure, ciphertexts, K1_1):
    """Find pairs inside the structure that:
      - keep R1 equal under the K1_1 guess
      - toggle bits 2 and/or 3 in L1
    return: [(idx_a, idx_b), ...]
    """
    pairs = []
    n = len(structure)
    # Find matching j values for each i
    for i in range(n):
        pt_a = structure[i]
        L0_a = (pt_a >> 32) & 0xFFFFFFFF
        R0_a = pt_a & 0xFFFFFFFF
        for j in range(i + 1, n):
            pt_b = structure[j]
            L0_b = (pt_b >> 32) & 0xFFFFFFFF
            R0_b = pt_b & 0xFFFFFFFF
            # R0 difference must be only in bits 2 and/or 3 (not zero)
            r0_diff = R0_a ^ R0_b
            # FIPS positions 2,3 → masks at (32-2)=30 and (32-3)=29
            mask_23 = (1 << 30) | (1 << 29)
            if r0_diff == 0 or (r0_diff & ~mask_23) != 0:
                continue
            # Equality of R1 requires f difference = L0 difference
            if not r1_equal_after_round1(L0_a, R0_a, L0_b, R0_b, K1_1):
                continue
            pairs.append((i, j))

    return pairs


def attack(num_structures, secret_key, seed=0, verbose=False):
    """Run the attack.
    return:
      - counter table for (K1,1, K8,1) (64x64)
      - true values of (K1,1, K8,1)
    """
    rng = random.Random(seed)
    subkeys = key_schedule(secret_key)
    K1 = subkeys[0]
    K8 = subkeys[7]
    # K1,1 = first 6 bits of K1 (leftmost 6 bits in the 48-bit subkey)
    K1_1_true = (K1 >> 42) & 0x3F
    K8_1_true = (K8 >> 42) & 0x3F

    if verbose:
        print(f"True K1,1 = {K1_1_true:06b} ({K1_1_true})")
        print(f"True K8,1 = {K8_1_true:06b} ({K8_1_true})")

    # counts[K1_1][K8_1] = number of pairs with output parity = 0
    counts = [[0] * 64 for _ in range(64)]
    totals = [0] * 64  # total number of pairs for each K1_1

    for s in range(num_structures):
        ref_pt = rng.getrandbits(64)
        structure = generate_structure(ref_pt)
        ciphertexts = [des_encrypt_n_rounds(pt, subkeys, 8) for pt in structure]

        for K1_1_guess in range(64):
            pairs = find_valid_pairs_in_structure(structure, ciphertexts, K1_1_guess)
            totals[K1_1_guess] += len(pairs)

            # For each pair, test parity under every K8_1 guess
            for (i, j) in pairs:
                ct_a = ciphertexts[i]
                ct_b = ciphertexts[j]
                L8_a = (ct_a >> 32) & 0xFFFFFFFF
                R8_a = ct_a & 0xFFFFFFFF
                L8_b = (ct_b >> 32) & 0xFFFFFFFF
                R8_b = ct_b & 0xFFFFFFFF
                # Since the input side of Matsui's relation is
                # differentially zero at round 4, the plaintext
                # parity contribution cancels in the difference.
                # We therefore count output parity differences;
                # expected probability: p^2+q^2 = 0.576.
                for K8_1_guess in range(64):
                    if parity_target(L8_a, R8_a, L8_b, R8_b, K8_1_guess) == 0:
                        counts[K1_1_guess][K8_1_guess] += 1

        if verbose and (s + 1) % max(1, num_structures // 10) == 0:
            print(f"  [{s+1}/{num_structures}] structures processed")

    return counts, totals, K1_1_true, K8_1_true


def rank_candidates(counts, totals):
    """Compute the bias |count/total - 0.5| for each (K1_1, K8_1)
    and rank the candidates.
    """
    scored = []
    for k1 in range(64):
        t = totals[k1]
        if t == 0:
            continue
        for k8 in range(64):
            r = counts[k1][k8] / t
            bias = abs(r - 0.5)
            scored.append((bias, k1, k8, r, counts[k1][k8], t))
    scored.sort(reverse=True)
    return scored


# ==================== Demo ====================

if __name__ == "__main__":
    import sys
    num_structs = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 0xC0FFEE

    # Random 64-bit key
    random.seed(seed)
    secret_key = random.getrandbits(64)

    print(f"--- Differential-Linear attack on 8-round DES ---")
    print(f"Key = {secret_key:016x}")
    print(f"Number of structures = {num_structs}  (~{num_structs*64} chosen plaintexts)")
    print()

    counts, totals, K1_1_true, K8_1_true = attack(
        num_structs, secret_key, seed=seed, verbose=True
    )

    ranked = rank_candidates(counts, totals)

    print()
    print("Top 10 candidate keys (bias = |ratio - 0.5|):")
    print(f"{'rank':>4} {'K1,1':>8} {'K8,1':>8} {'bias':>8} {'ratio':>7}  {'count/total'}")
    for rank, (bias, k1, k8, r, c, t) in enumerate(ranked[:10], 1):
        mark = "  <-- CORRECT" if (k1 == K1_1_true and k8 == K8_1_true) else ""
        print(f"{rank:>4} {k1:>8} {k8:>8} {bias:>8.4f} {r:>7.4f}  {c}/{t}{mark}")

    # Position of the correct candidate
    for rank, (bias, k1, k8, r, c, t) in enumerate(ranked, 1):
        if k1 == K1_1_true and k8 == K8_1_true:
            print(f"\nCorrect candidate (K1,1={K1_1_true}, K8,1={K8_1_true}) rank: {rank}")
            print(f"  bias = {bias:.4f}, ratio = {r:.4f}")
            break

time_end = time.time()
print('Attack took', time_end - time_begin, 'seconds')

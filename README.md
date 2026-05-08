# Langford-Hellman Differential-Linear Attack on 8-round DES

Python implementation of the Langford & Hellman paper from CRYPTO '94.

## Files

- **`des_core.py`** — Core building blocks of DES: S-boxes, E / P / PC1 / PC2
  permutations, key schedule, f-function, and n-round encryption
  (IP and IP⁻¹ are omitted — as in the paper).
- **`dl_attack.py`** — The attack itself. Structure generation, K₁,₁ guessing
  via round 1, K₈,₁ guessing via round 8, and verification of Matsui's
  3-round parity relation.
- **`test_success_rate.py`** — Runs the attack on multiple random keys
  and measures the success rate.

## Idea of the attack (very briefly)

1. **Structure:** Take a reference plaintext and vary bits 9, 17, 23, 31 of L₀
   together with bits 2 and 3 of R₀ through all combinations → 2⁶ = 64 plaintexts.
   (These 4 bits in L₀ correspond, after the P permutation, to the output
   positions of S₁.)

2. **K₁,₁ guess (6 bits):** From the structure, find pairs whose R₁ values
   are equal after round 1. Since
   R₁ = L₀ ⊕ f(R₀, K₁),
   the L₀ difference must equal the f-function difference for two plaintexts
   in the structure. Since only the S₁ input changes, the guess is limited
   to 6 bits.

3. **Differential characteristic (rounds 1 → 4, probability 1):**
   R₁' = 0 and L₁' toggles only in bits 2 and 3 ⇒
   bits 3, 8, 14, 25 of L₄' and bit 17 of R₄'
   are differentially zero.

4. **Matsui's 3-round linear relation (rounds 5 → 7):**
   L₄[3,8,14,25] ⊕ R₄[17]
   =
   R₇[3,8,14,25] ⊕ L₇[17] ⊕ (key bits)

   with probability p = 0.695.
   Taking XOR over a *pair* cancels the key bits, yielding an expected bias
   of p² + q² = 0.576.

5. **K₈,₁ guess (6 bits):** To partially decrypt round 8, we use

   L₇[17] = R₈[17] ⊕ f(L₈, K₈)[17]

   By the P permutation, the 17th output bit of f depends only on S₁,
   so 6 bits are sufficient.

6. **Counting:** For every
   (K₁,₁, K₈,₁) ∈ 2¹² guess,
   count how many pairs have output parity equal to 0.
   For the correct guess the ratio is approximately 0.576,
   while for wrong guesses it is approximately 0.5.
   Sorting by |ratio − 0.5| places the correct candidate at the top.

   Note: The paper states that K₁,₁ and K₈,₁ share two bits, reducing the
   *effective* guess space to 2¹⁰ = 1024. This simple implementation does
   not enforce that sharing (it uses 64 × 64 = 4096 counters instead),
   but this does not affect the results — inconsistent combinations naturally
   receive low scores.

## Running

```bash
# Single run: 8 structures ≈ 512 chosen plaintexts, fixed seed 42
python dl_attack.py 8 42
# Single run: 12 structures ≈ 768 chosen plaintexts, fixed seed 25
python dl_attack.py 12 25

# Measure success rate over multiple trials:
python test_success_rate.py 8 10 8     # 8 structures, 10 trials, top-8
python test_success_rate.py 12 10 1    # 12 structures, 10 trials, top-1

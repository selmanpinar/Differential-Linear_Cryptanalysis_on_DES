"""
Langford-Hellman (CRYPTO '94) 8-round DES'e Differential-Linear saldırısı.

Saldırı özeti:
  - Yapı (structure): L0'ın 9,17,23,31 bitleri (S1'in çıktıları) ve R0'ın 2,3
    bitleri varyasyonlu, diğer bitler sabit. Toplam 2^6 = 64 plaintext.
  - K1,1 (S1'in alt-anahtarı) doğru tahmin edilirse round 1'de yalnızca
    S1'in çıktısı etkilenir; böylece R1 aynı kalır ve L1'de 2 ve/veya 3.
    bit toggle edilmiş bir çift elde ederiz.
  - Round 2-4 boyunca diferansiyel karakteristik (Şekil 3):
      R1' = 0, L1' = sadece bit 2,3 toggle
      => L4'ün 3,8,14,25. bitleri ve R4'ün 17. biti diferansiyel olarak 0.
  - Matsui'nin 3-round parity ilişkisi (round 5-7):
      L4[3,8,14,25] ⊕ R4[17] = R7[3,8,14,25] ⊕ L7[17] ⊕ anahtar bitleri
      olasılık p = 0.695. İki koşum üzerinde XOR'landığında p^2+q^2 = 0.576.
  - Round 8'i geri çözmek için K8,1 tahmini: L7[17] = R8[17] XOR
    (f(L8, K8) üzerinden sadece S1'in katkısı).
  - Toplam tahmin: (K1,1, K8,1). Ortak 2 bit olduğundan etkin 10 bit.

Bu dosya:
  - generate_structure: bir yapı üretir
  - attack: çok sayıda yapı ile (K1,1, K8,1) için sayaç tablosu kurar
"""

import random
from traceback import print_tb

from des_core import (
    key_schedule, des_encrypt_n_rounds, f_function,
    permute, E, P, sbox_lookup, get_bit,
)

# ---- FIPS (MSB=1) → bit pozisyonları ----

import time

time_begin = time.time()

def bit_from_left(val, pos, width=32):
    """pos: 1..width, 1 = MSB (soldan birinci bit)."""
    return (val >> (width - pos)) & 1


def set_bit_left(val, pos, b, width=32):
    """pos. biti b yap."""
    mask = 1 << (width - pos)
    return (val & ~mask) | ((b & 1) << (width - pos))


def flip_bit_left(val, pos, width=32):
    return val ^ (1 << (width - pos))


# ==================== Yapı üretimi ====================

# S1'in P permütasyonundan sonra R'da etkilediği 4 bit pozisyonu.
# P tablosu indeks[0..3] S1'in 4 çıkış bitinin nereye gittiğini verir.
# P[0]=16, P[1]=7, P[2]=20, P[3]=21  -> R çıktı bitleri 1,2,3,4
# (FIPS'te pos 1..32 arası, P tablosundaki değer: kaynak bit).
# Bizim ihtiyacımız: permütasyon sonrası R'daki hangi 4 bit S1'den geliyor.
# P fonksiyonundan sonra çıktının i. biti, kaynakta P[i-1]. bittir.
# Kaynak (S-box çıkışı öncesi) bit 1..4 S1'dir.
# Dolayısıyla çıktının i. biti S1'den ise P[i-1] ∈ {1,2,3,4}.
# P listesinden: P[i]=16 → çıktı bit 1, P[i]=7 → çıktı bit 2, vb. değil;
# tam tersi: output[i] = input[P[i-1]]. Biz P'nin inverse'ini kullanacağız.

def compute_S1_output_positions_after_P():
    """P permütasyonundan sonra S1'den gelen (kaynak bit 1..4)
    32-bit çıktıdaki pozisyonları döner (FIPS, MSB=1)."""
    positions = []
    for out_pos, src in enumerate(P, start=1):
        if src in (1, 2, 3, 4):
            positions.append(out_pos)
    return sorted(positions)

S1_OUTPUT_POSITIONS = compute_S1_output_positions_after_P()
# Makaleden: 9, 17, 23, 31 olmalı
assert S1_OUTPUT_POSITIONS == [9, 17, 23, 31], f"Beklenen [9,17,23,31], bulunan {S1_OUTPUT_POSITIONS}"


def generate_structure(reference_plaintext):
    """Referans plaintext'ten 64 plaintext'lik yapı üret.
    Varyasyonlu bitler:
      - L0'ın 9, 17, 23, 31. bitleri (S1'in çıktısı olan konumlar)
      - R0'ın 2, 3. bitleri
    Toplam 6 bit -> 64 plaintext.
    """
    L0_ref = (reference_plaintext >> 32) & 0xFFFFFFFF
    R0_ref = reference_plaintext & 0xFFFFFFFF
    L_vary_pos = [9, 17, 23, 31]  # L0'da
    R_vary_pos = [2, 3]           # R0'da
    plaintexts = []
    for mask in range(64):
        L0 = L0_ref
        R0 = R0_ref
        # L0 varyasyonları
        for i, pos in enumerate(L_vary_pos):
            b = (mask >> (5 - i)) & 1
            L0 = set_bit_left(L0, pos, b)
        # R0 varyasyonları
        for i, pos in enumerate(R_vary_pos):
            b = (mask >> (1 - i)) & 1
            R0 = set_bit_left(R0, pos, b)
        plaintexts.append((L0 << 32) | R0)


    return plaintexts


# ==================== Round 1 & Round 8 üzerinden S1 hesapları ====================

def s1_input_at_round1(L0, R0, K1_1):
    """Round 1'de S1'in çıktısını ve etkilediği L1 bitlerini hesapla.
    Tam f'yi değil, sadece S1 üzerinden bu 4 biti sağlar.
    return: (L1, R1) — ama yalnızca S1 katkısı dikkate alınır; diğer bitler
    ref ile aynı olur, bu yüzden differential iz için yeterli.
    Aslında biz tam f_function gerekli değil — yalnızca 'aynı K1,1 altında
    pair oluşturma' mantığı için L1'deki bit 2,3'ün değeri bilinmeli.
    """
    # E genişletme sonrası S1 girişi: E tablosundaki ilk 6 pozisyon
    # E[0..5] = [32, 1, 2, 3, 4, 5] → R0'ın 32,1,2,3,4,5. bitleri
    e_bits = 0
    for src in E[:6]:
        e_bits = (e_bits << 1) | bit_from_left(R0, src, 32)
    s1_in = e_bits ^ ((K1_1 >> 0) & 0x3F)
    return sbox_lookup(0, s1_in)  # 4-bit çıktı


def l1_bits_2_3(L0, R0, K1_1):
    """Round 1 sonrası L1 = R0'dır (swap'siz Feistel'de L1=R0).
    Aslında standart DES: L1 = R0, R1 = L0 XOR f(R0,K1).
    L1'in 2 ve 3. bitleri = R0'ın 2 ve 3. bitleri.
    Dolayısıyla K1,1'in bir fonksiyonu DEĞİL! 
    
    DUR - burada dikkatli olmalıyız: saldırıda istenen, R1'in toggle
    olmaması, L1'in bit 2,3'ünün toggle olmasıdır. L1=R0 olduğuna göre
    bunlar zaten plaintext tarafından kontrol ediliyor. K1,1 tahmini ise
    R1'i doğru tutmak için: R1 = L0 XOR f(R0, K1). Yapı içindeki iki PT
    için R1'lerin aynı olması ⇔ L0 farkı = f farkı olması.
    """
    return (bit_from_left(R0, 2), bit_from_left(R0, 3))


def r1_equal_after_round1(L0_a, R0_a, L0_b, R0_b, K1_1):
    """İki plaintext için round 1 sonrası R1'lerin aynı olup olmadığını
    kontrol eder. Yalnızca K1,1 girdi farkını etkiler (çünkü R0_a ve R0_b
    sadece bit 2,3'te farklıdır; bu bitler E ile sadece S1'e gider).
    
    R1 = L0 XOR f(R0, K1). R1_a XOR R1_b = L0_a XOR L0_b XOR
         f(R0_a,K1) XOR f(R0_b,K1).
    f farkı yalnızca S1'den gelir (diğer S-box'lar aynı giriş alır).
    Bu nedenle K1,1 (6 bit) yeterli.
    """
    # S1 çıktı farkı
    s1_a = sbox_output_from_R(R0_a, K1_1)
    s1_b = sbox_output_from_R(R0_b, K1_1)
    f_diff = s1_a ^ s1_b  # 32-bit, sadece S1 çıkışlı pozisyonlarda sıfırdan farklı olabilir
    l0_diff = L0_a ^ L0_b
    return (l0_diff ^ f_diff) == 0


def sbox_output_from_R(R, K1_1):
    """Sadece S1'in P sonrası katkısını 32-bit olarak döner (diğer S-box
    çıkışları sıfır olarak).
    """
    # S1'in girişi: E(R)'nin ilk 6 biti ^ K1_1
    e_bits = 0
    for src in E[:6]:
        e_bits = (e_bits << 1) | bit_from_left(R, src, 32)
    s1_in = e_bits ^ (K1_1 & 0x3F)
    s1_out = sbox_lookup(0, s1_in)  # 4-bit
    # 32-bit düzenle: S1 çıktısı, S-box pre-permutation'da en soldaki 4 bit
    sbox_out_32 = s1_out << 28
    return permute(sbox_out_32, P, 32)


# ==================== Round 8'den L7[17] hesabı ====================

def compute_L7_bit17(L8, R8, K8_1):
    """Ciphertext (L8, R8) ve K8,1 tahmininden L7[17]'i hesapla.
    
    Feistel: L8 = R7, R8 = L7 XOR f(R7, K8) = L7 XOR f(L8, K8).
    Dolayısıyla L7 = R8 XOR f(L8, K8).
    L7[17] = R8[17] XOR f(L8, K8)[17].
    
    P permütasyonundan: çıktı bit 17 kaynak bit P[16]=2, yani S-box
    çıkışı öncesi bit 2. S-box öncesi bit 2 = S1'in 2. çıktı biti (S1'in
    çıktı bitleri 1..4'tür). Dolayısıyla f'nin 17. çıktı biti SADECE S1'e
    bağlıdır → K8,1 (6 bit) yeterli.
    """
    # E(L8)'in ilk 6 biti S1'e gider
    e_bits = 0
    for src in E[:6]:
        e_bits = (e_bits << 1) | bit_from_left(L8, src, 32)
    s1_in = e_bits ^ (K8_1 & 0x3F)
    s1_out = sbox_lookup(0, s1_in)  # 4 bit
    # S1 çıktı bit 2 = (s1_out >> 2) & 1   (MSB=bit1)
    s1_bit2 = (s1_out >> 2) & 1
    # P sonrası bu, 32-bit çıktının 17. bitine gider
    f_bit17 = s1_bit2
    return bit_from_left(R8, 17) ^ f_bit17


# ==================== Ana saldırı ====================

def parity_target(L8_a, R8_a, L8_b, R8_b, K8_1):
    """İki ciphertext üzerinde Matsui'nin 3-round ilişkisinin
    output parity'sinin toplamını döner:
        [R7_a[3,8,14,25] XOR L7_a[17]] XOR [R7_b[3,8,14,25] XOR L7_b[17]]
    = (R7 = L8 olduğundan, R7[i] = L8[i])
    """
    # R7_a[3,8,14,25] XOR L7_a[17]
    def side(L8, R8):
        p = 0
        for pos in (3, 8, 14, 25):
            p ^= bit_from_left(L8, pos, 32)
        p ^= compute_L7_bit17(L8, R8, K8_1)
        return p
    return side(L8_a, R8_a) ^ side(L8_b, R8_b)


def find_valid_pairs_in_structure(structure, ciphertexts, K1_1):
    """Yapı içinde K1_1 tahminine göre round 1'de R1'i aynı tutan
    ve L1'de bit 2 ve/veya 3'ü toggle eden çiftleri bul.
    return: [(idx_a, idx_b), ...]
    """
    pairs = []
    n = len(structure)
    # Her i için eşleştirici j'leri bul
    for i in range(n):
        pt_a = structure[i]
        L0_a = (pt_a >> 32) & 0xFFFFFFFF
        R0_a = pt_a & 0xFFFFFFFF
        for j in range(i + 1, n):
            pt_b = structure[j]
            L0_b = (pt_b >> 32) & 0xFFFFFFFF
            R0_b = pt_b & 0xFFFFFFFF
            # R0'ların farkı sadece bit 2 ve/veya 3'te olmalı (0 değil)
            r0_diff = R0_a ^ R0_b
            # FIPS pos 2,3 → bit maskesi (32-2)=30 ve (32-3)=29
            mask_23 = (1 << 30) | (1 << 29)
            if r0_diff == 0 or (r0_diff & ~mask_23) != 0:
                continue
            # R1'lerin aynı olması için f farkı = L0 farkı
            if not r1_equal_after_round1(L0_a, R0_a, L0_b, R0_b, K1_1):
                continue
            pairs.append((i, j))

    return pairs


def attack(num_structures, secret_key, seed=0, verbose=False):
    """Saldırıyı çalıştır. 
    return: (K1_1, K8_1) için sayaç tablosu (64x64),
            ve doğru (K1,1, K8,1) değerleri.
    """
    rng = random.Random(seed)
    subkeys = key_schedule(secret_key)
    K1 = subkeys[0]
    K8 = subkeys[7]
    # K1,1 = K1'in ilk 6 biti (48 bit içinde en soldaki 6 bit)
    K1_1_true = (K1 >> 42) & 0x3F
    K8_1_true = (K8 >> 42) & 0x3F

    if verbose:
        print(f"Gerçek K1,1 = {K1_1_true:06b} ({K1_1_true})")
        print(f"Gerçek K8,1 = {K8_1_true:06b} ({K8_1_true})")

    # counts[K1_1][K8_1] = (output parity = 0) olan pair sayısı
    counts = [[0] * 64 for _ in range(64)]
    totals = [0] * 64  # her K1_1 için toplam pair sayısı

    for s in range(num_structures):
        ref_pt = rng.getrandbits(64)
        structure = generate_structure(ref_pt)
        ciphertexts = [des_encrypt_n_rounds(pt, subkeys, 8) for pt in structure]

        for K1_1_guess in range(64):
            pairs = find_valid_pairs_in_structure(structure, ciphertexts, K1_1_guess)
            totals[K1_1_guess] += len(pairs)

            # Her pair için, her K8_1 tahmininde parity'yi kontrol et
            for (i, j) in pairs:
                ct_a = ciphertexts[i]
                ct_b = ciphertexts[j]
                L8_a = (ct_a >> 32) & 0xFFFFFFFF
                R8_a = ct_a & 0xFFFFFFFF
                L8_b = (ct_b >> 32) & 0xFFFFFFFF
                R8_b = ct_b & 0xFFFFFFFF
                # Plaintext parity (Matsui ilişkisinin girdi tarafı round 4'te
                # differential olarak 0 olduğundan, plaintext parity katkısı
                # fark üzerinden sıfırlanır). Yine de biz çıktı parity farkını
                # sayıyoruz; beklenen p^2+q^2 = 0.576.
                for K8_1_guess in range(64):
                    if parity_target(L8_a, R8_a, L8_b, R8_b, K8_1_guess) == 0:
                        counts[K1_1_guess][K8_1_guess] += 1

        if verbose and (s + 1) % max(1, num_structures // 10) == 0:
            print(f"  [{s+1}/{num_structures}] yapı işlendi")

    return counts, totals, K1_1_true, K8_1_true


def rank_candidates(counts, totals):
    """Her (K1_1, K8_1) için |count/total - 0.5| biasını hesapla ve sırala."""
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

    # Rastgele bir 64-bit anahtar
    random.seed(seed)
    secret_key = random.getrandbits(64)

    print(f"--- Differential-Linear saldırısı, 8-round DES ---")
    print(f"Anahtar = {secret_key:016x}")
    print(f"Yapı sayısı = {num_structs}  (~{num_structs*64} chosen plaintexts)")
    print()

    counts, totals, K1_1_true, K8_1_true = attack(
        num_structs, secret_key, seed=seed, verbose=True
    )

    ranked = rank_candidates(counts, totals)

    print()
    print("En olası 10 aday (bias = |ratio - 0.5|):")
    print(f"{'sıra':>4} {'K1,1':>8} {'K8,1':>8} {'bias':>8} {'ratio':>7}  {'count/total'}")
    for rank, (bias, k1, k8, r, c, t) in enumerate(ranked[:10], 1):
        mark = "  <-- DOĞRU" if (k1 == K1_1_true and k8 == K8_1_true) else ""
        print(f"{rank:>4} {k1:>8} {k8:>8} {bias:>8.4f} {r:>7.4f}  {c}/{t}{mark}")

    # Doğru aday nerede?
    for rank, (bias, k1, k8, r, c, t) in enumerate(ranked, 1):
        if k1 == K1_1_true and k8 == K8_1_true:
            print(f"\nDoğru (K1,1={K1_1_true}, K8,1={K8_1_true}) adayın sırası: {rank}")
            print(f"  bias = {bias:.4f}, ratio = {r:.4f}")
            break

time_end = time.time()
print('Atak', time_end - time_begin, 'saniye sürdü')
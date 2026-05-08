"""
DES temel yapı taşları: S-box'lar, permütasyonlar, key schedule, f fonksiyonu.
FIPS PUB 46 bit numaralandırması kullanılır (soldan sağa, 1'den başlayarak).
Makalede olduğu gibi IP ve IP^-1 ihmal edilir (kripto-analitik açıdan önemsiz).
"""

# ---- S-box'lar (DES standardı) ----
S_BOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]

# ---- Expansion (E) permütasyonu: 32 -> 48 ----
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# ---- P permütasyonu (S-box çıktılarından sonra) ----
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# ---- Key schedule ----
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# ==================== Yardımcı fonksiyonlar ====================

def permute(block, table, n_in):
    """FIPS bit numaralandırmasıyla permütasyon.
    block: tamsayı (n_in bit genişliğinde, MSB=bit 1).
    table: her eleman 1..n_in arası kaynak bit numarası.
    return: len(table)-bit tamsayı (MSB=çıktının 1. biti).
    """
    out = 0
    for i, src in enumerate(table):
        # src. biti al (MSB=1)
        bit = (block >> (n_in - src)) & 1
        out = (out << 1) | bit
    return out


def get_bit(block, pos, width):
    """FIPS numaralandırması: pos=1 MSB."""
    return (block >> (width - pos)) & 1


def sbox_lookup(sbox_idx, six_bits):
    """6-bit giriş -> 4-bit çıkış. S-box indeksi 0..7."""
    # Makaledeki notasyona göre giriş (x1,x2,x3,x4,x5,x6), x1=MSB
    row = ((six_bits >> 5) & 1) * 2 + (six_bits & 1)
    col = (six_bits >> 1) & 0x0F
    return S_BOXES[sbox_idx][row][col]


def f_function(R, subkey):
    """DES round fonksiyonu: 32-bit R + 48-bit subkey -> 32-bit çıktı."""
    # Genişletme
    expanded = permute(R, E, 32)
    # XOR
    x = expanded ^ subkey
    # S-box'lar
    sbox_out = 0
    for i in range(8):
        six = (x >> (42 - 6 * i)) & 0x3F
        sbox_out = (sbox_out << 4) | sbox_lookup(i, six)
    # P permütasyonu
    return permute(sbox_out, P, 32)


# ==================== Key schedule ====================

def key_schedule(key64):
    """64-bit anahtardan 16 adet 48-bit alt-anahtar üret."""
    # PC1: 64 -> 56 bit
    key56 = permute(key64, PC1, 64)
    C = (key56 >> 28) & 0x0FFFFFFF
    D = key56 & 0x0FFFFFFF

    def lrot28(v, n):
        return ((v << n) | (v >> (28 - n))) & 0x0FFFFFFF

    subkeys = []
    for r in range(16):
        C = lrot28(C, SHIFTS[r])
        D = lrot28(D, SHIFTS[r])
        CD = (C << 28) | D
        subkeys.append(permute(CD, PC2, 56))
    return subkeys


# ==================== DES şifreleme (N round, IP yok) ====================

def des_encrypt_n_rounds(plaintext64, subkeys, n_rounds):
    """IP ve IP^-1 olmadan n-round DES.
    plaintext64: 64-bit tamsayı, (L0,R0) olarak yorumlanır.
    return: 64-bit (Ln, Rn).
    """
    L = (plaintext64 >> 32) & 0xFFFFFFFF
    R = plaintext64 & 0xFFFFFFFF
    for i in range(n_rounds):
        L, R = R, L ^ f_function(R, subkeys[i])
    return (L << 32) | R


# ==================== Hızlı sanity check ====================

if __name__ == "__main__":
    # Basit sanity: f fonksiyonu çıktıları 32 bit olmalı
    import random
    random.seed(0)
    key = random.getrandbits(64)
    sks = key_schedule(key)
    print(f"Örnek 48-bit subkey K1: {sks[0]:012x}")
    pt = random.getrandbits(64)
    ct = des_encrypt_n_rounds(pt, sks, 8)
    print(f"PT={pt:016x}  -> CT (8 round)={ct:016x}")
    print("DES core sanity OK.")

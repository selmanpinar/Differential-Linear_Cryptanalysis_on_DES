# Langford-Hellman Differential-Linear Attack on 8-round DES

CRYPTO '94'teki Langford & Hellman makalesinin Python implementasyonu.

## Dosyalar

- **`des_core.py`** — DES'in temel yapı taşları: S-box'lar, E / P / PC1 / PC2
  permütasyonları, key schedule, f-fonksiyonu, n-round şifreleme
  (IP ve IP⁻¹ ihmal edilir — makaledeki gibi).
- **`dl_attack.py`** — Saldırının kendisi. Yapı (structure) üretimi, round 1
  üzerinden K₁,₁ tahmini, round 8 üzerinden K₈,₁ tahmini ve Matsui'nin
  3-round parity ilişkisinin kontrolü.
- **`test_success_rate.py`** — Birden çok rastgele anahtarla saldırıyı
  çalıştırıp başarı oranını ölçer.

## Saldırının mantığı (çok kısa)

1. **Yapı:** Referans bir plaintext al, L₀'ın 9, 17, 23, 31. bitleri + R₀'ın 2, 3.
   bitlerini tüm kombinasyonlarda varyasyona sok → 2⁶ = 64 plaintext.
   (L₀'daki bu 4 bit, P permütasyonu sonrası S₁'in çıktısının konumlarıdır.)

2. **K₁,₁ tahmini (6 bit):** Yapı içinden, round 1 sonrası R₁'i aynı tutan
   çiftler bulunur. R₁ = L₀ ⊕ f(R₀, K₁) olduğundan, yapı iki PT'si için
   L₀ farkı = f farkı olmalıdır. Yalnızca S₁'in girdisi değiştiğinden tahmin
   6 bit ile sınırlıdır.

3. **Diferansiyel karakteristik (round 1 → 4, olasılık 1):**
   R₁' = 0, L₁' yalnızca bit 2, 3'te toggle ⇒
   L₄'ün 3, 8, 14, 25 bitleri ve R₄'ün 17. biti diferansiyel olarak 0.

4. **Matsui 3-round doğrusal ilişkisi (round 5 → 7):**
   L₄[3, 8, 14, 25] ⊕ R₄[17] = R₇[3, 8, 14, 25] ⊕ L₇[17] ⊕ (anahtar bitleri)
   — olasılık p = 0.695.
   Bir *çift* üzerinde XOR alınınca anahtar bitleri düşer ve beklenen sapma
   p² + q² = 0.576 olur.

5. **K₈,₁ tahmini (6 bit):** Round 8'i geri çözmek için L₇[17] = R₈[17] ⊕
   f(L₈, K₈)[17] gerekir. P permütasyonundan f'nin 17. çıkış biti yalnızca
   S₁'e bağlıdır → 6 bit yeterli.

6. **Sayım:** Her (K₁,₁, K₈,₁) ∈ 2¹² tahmini için, çıkış parity'si 0 olan
   çift sayısı sayılır. Doğru tahminde oran ≈ 0.576, yanlış tahminlerde ≈ 0.5.
   |oran − 0.5| sıralamasında doğru aday en üstte çıkar.

   Not: Makalede K₁,₁ ve K₈,₁ iki bit paylaştığı söylenir; böylece *etkin*
   tahmin uzayı 2¹⁰ = 1024'tür. Bizim basit implementasyon paylaşımı
   uygulamaz (64 × 64 = 4096 sayacı kullanır), ama sonuçları etkilemez —
   çakışmayan kombinasyonlar zaten düşük skor alır.

## Çalıştırma

```bash
# Tek deneme: 8 yapı ≈ 512 seçilmiş düz metin, sabit seed
python dl_attack.py 8 42

# Birden çok denemeyle başarı oranı ölç:
python test_success_rate.py 8 10 8     # 8 yapı, 10 deneme, liste boyutu 8
python test_success_rate.py 12 10 1    # 12 yapı, 10 deneme, top-1
```

## Beklenen sonuçlar (makaleye göre)

| Yapı sayısı | Chosen PT | Beklenen Top-1 | Liste 8 ile Top-N |
|:-:|:-:|:-:|:-:|
| 8  | 512 | %80 | %95 |
| 12 | 768 | %95 | — |

Pratikte 10 denemede elde edilen: **Top-1 %90, Top-8 %100** (8 yapı ile).

## Uyarılar

- Saf Python'da yazıldığı için çok hızlı değildir. 8 yapı × 64 tahmin × çift
  sayısı × 64 iç tahmin döngüsü yaklaşık 1 dakika sürer.
- FIPS bit numaralandırması (MSB = bit 1) kullanılır — makaledeki gösterime uymak için.
- IP ve IP⁻¹ permütasyonları uygulanmaz (kripto-analitik olarak önemsiz).

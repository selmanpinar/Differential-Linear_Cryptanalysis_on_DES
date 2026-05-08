"""
Makaledeki başarı oranlarını doğrula:
  - 8 yapı (512 chosen PT) ->  %80 başarı beklentisi
  - 12 yapı (768 chosen PT) -> %95 başarı beklentisi
"""

import random
import sys
from dl_attack import attack, rank_candidates


def run_trials(num_structs, num_trials, list_size=1):
    """num_trials rastgele anahtarla saldırıyı çalıştır."""
    top1_hits = 0
    topN_hits = 0
    ranks = []
    for trial in range(num_trials):
        seed = 1000 + trial
        random.seed(seed)
        key = random.getrandbits(64)
        counts, totals, K1_true, K8_true = attack(num_structs, key, seed=seed)
        ranked = rank_candidates(counts, totals)
        # Doğru aday kaçıncı?
        found_rank = None
        for r, (_, k1, k8, *_rest) in enumerate(ranked, 1):
            if k1 == K1_true and k8 == K8_true:
                found_rank = r
                break
        ranks.append(found_rank)
        if found_rank == 1:
            top1_hits += 1
        if found_rank is not None and found_rank <= list_size:
            topN_hits += 1
        print(f"  trial {trial+1:2d}: (K1,1={K1_true:2d}, K8,1={K8_true:2d}) "
              f"sıra={found_rank}")
    print(f"\n--- {num_structs} yapı, {num_trials} deneme ---")
    print(f"Top-1 başarı: {top1_hits}/{num_trials} = {100*top1_hits/num_trials:.1f}%")
    if list_size > 1:
        print(f"Top-{list_size} başarı: {topN_hits}/{num_trials} = {100*topN_hits/num_trials:.1f}%")
    print(f"Sıralamalar: {ranks}")
    return top1_hits, topN_hits


if __name__ == "__main__":
    num_structs = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    num_trials = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    list_size = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    run_trials(num_structs, num_trials, list_size)

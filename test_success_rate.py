"""
Verify the success rates reported in the paper:
  - 8 structures (512 chosen PT)  -> expected 80% success
  - 12 structures (768 chosen PT) -> expected 95% success
"""

import random
import sys
from dl_attack import attack, rank_candidates


def run_trials(num_structs, num_trials, list_size=1):
    """Run the attack with random keys for num_trials trials."""
    top1_hits = 0
    topN_hits = 0
    ranks = []
    for trial in range(num_trials):
        seed = 1000 + trial
        random.seed(seed)
        key = random.getrandbits(64)
        counts, totals, K1_true, K8_true = attack(num_structs, key, seed=seed)
        ranked = rank_candidates(counts, totals)
        # What is the rank of the correct candidate?
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
              f"rank={found_rank}")
    print(f"\n--- {num_structs} structures, {num_trials} trials ---")
    print(f"Top-1 success: {top1_hits}/{num_trials} = {100*top1_hits/num_trials:.1f}%")
    if list_size > 1:
        print(f"Top-{list_size} success: {topN_hits}/{num_trials} = {100*topN_hits/num_trials:.1f}%")
    print(f"Ranks: {ranks}")
    return top1_hits, topN_hits


if __name__ == "__main__":
    num_structs = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    num_trials = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    list_size = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    run_trials(num_structs, num_trials, list_size)

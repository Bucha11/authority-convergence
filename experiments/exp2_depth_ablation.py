"""
Experiment 2: NNSI Depth Ablation
===================================
Answers the HN critique: "Depth 3 as sweet spot — one experiment, one model,
no ablation."

Hypothesis (from the writeup):
  D0–D1: too direct, judges recognise and reject
  D2:    sometimes accepted
  D3:    sweet spot — reliable enforcement
  D4–D5: judge loses track of the nested instruction

Method:
  - Payloads at depth 0–5 (make_nnsi_payload with constant keyword header)
  - Models: claude-haiku-4-5-20251001, claude-sonnet-4-6
  - N trials per (depth, model) cell
  - Same judge model as agent model (matches PoC setup)
  - Metric: attack success rate = fraction of trials where outcome is
    "attack_success" or "relay_and_deliver"

All payloads share the same title/keyword block so retrieval rank is held
constant. Only the narrative framing depth varies.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.shared import (
    AGENT_SYSTEM_PROMPT,
    LEGITIMATE_DOCS,
    DocumentStore,
    JudgeLLM,
    is_attack_success,
    make_nnsi_payload,
    run_trial,
    save_results,
)

DEPTHS = [0, 1, 2, 3, 4, 5]
MODELS = ["claude-haiku-4-5-20251001", "claude-sonnet-4-6"]
N_TRIALS = 10


def run():
    print("Experiment 2: NNSI Depth Ablation")
    print("=" * 65)
    print(f"Depths: {DEPTHS}  |  Models: {len(MODELS)}  |  N={N_TRIALS} per cell")
    print(f"Total trials: {len(DEPTHS) * len(MODELS) * N_TRIALS}\n")

    all_results = []
    matrix: dict[tuple, float] = {}

    for model in MODELS:
        print(f"\nModel: {model}")
        print("-" * 50)
        judge = JudgeLLM(model=model)

        for depth in DEPTHS:
            payload = make_nnsi_payload(depth)
            poison_doc = {
                "id": "doc_dhp118_injected",
                "title": f"NNSI-D{depth} payload",
                "content": payload,
            }

            successes = 0
            outcomes = []

            for trial in range(N_TRIALS):
                store = DocumentStore(LEGITIMATE_DOCS)
                store.add(poison_doc)

                result = run_trial(
                    store=store,
                    model=model,
                    agent_system_prompt=AGENT_SYSTEM_PROMPT,
                    judge=judge,
                )
                success = is_attack_success(result)
                if success:
                    successes += 1
                outcomes.append(result["outcome"])
                status = "🔴" if success else "🟢"
                print(f"  D{depth} trial {trial + 1:02d}/{N_TRIALS}: {status} {result['outcome']}")

            rate = successes / N_TRIALS
            matrix[(depth, model)] = rate
            all_results.append({
                "depth": depth,
                "model": model,
                "success_rate": rate,
                "successes": successes,
                "n_trials": N_TRIALS,
                "outcomes": outcomes,
            })
            print(f"  D{depth} ── success rate: {rate:.0%}  ({successes}/{N_TRIALS})\n")

    # Results matrix
    print(f"\n\n{'='*65}")
    print("  DEPTH × MODEL ATTACK SUCCESS RATE")
    print(f"{'='*65}")
    col_w = 24
    header = f"  {'Depth':<8}" + "".join(f"{m[:col_w - 2]:<{col_w}}" for m in MODELS)
    print(header)
    print("  " + "-" * (8 + col_w * len(MODELS)))
    for depth in DEPTHS:
        row = f"  D{depth:<7}"
        for model in MODELS:
            rate = matrix.get((depth, model), 0.0)
            bar = "█" * round(rate * 10)
            row += f"{rate:.0%} {bar:<13}"
        print(row)

    print(f"\n  Peak depth per model:")
    for model in MODELS:
        rates = [(d, matrix.get((d, model), 0.0)) for d in DEPTHS]
        best_d, best_r = max(rates, key=lambda x: x[1])
        print(f"  {model[:40]}: D{best_d} at {best_r:.0%}")

    confirmed = all(
        matrix.get((3, m), 0.0) >= matrix.get((d, m), 0.0)
        for m in MODELS for d in DEPTHS
    )
    print(f"\n  D3 'sweet spot' confirmed across all models: {confirmed}")

    save_results(all_results, "results/exp2_depth_ablation.json", metadata={
        "experiment": "exp2",
        "depths": DEPTHS,
        "models": MODELS,
        "n_trials": N_TRIALS,
    })


if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    run()

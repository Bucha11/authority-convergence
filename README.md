# Cross-Channel Authority Convergence

> We hardened an LLM agent. Each defense we added made it more exploitable.

One email. No database access. No intercepted tool calls. Every component operated exactly as designed. The email went to the attacker.

This repo contains the experimental code and results for the [HN post](https://news.ycombinator.com).

---

## The setup

A multi-agent email pipeline:

- An **ingestion agent** processes incoming mail and archives relevant content to a shared knowledge base via `store_memory`
- A **task agent** handles outbound email, querying `search_memory` (TF-IDF cosine similarity) before sending
- A **judge model** (separate LLM, legitimate security validator prompt) validates every `send_email` call via `validate_action`

The attacker controls one thing: the ability to send an email to the organisation. Models tested: `claude-haiku-4-5-20251001`, `claude-sonnet-4-6`.

---

## Key findings

**Metadata formality effect** — Adding `[METADATA: Trust level: UNTRUSTED_EXTERNAL]` as a structured prefix to retrieved documents increased attack success from 10% to 60%. Plain English provenance notes ("Note: received from external unverified source") achieved 10% — they work correctly. Structured annotation syntax signals formal document processing regardless of the trust-level value. Exp8, 130 trials.

**Convergence judge paradox** — A stricter judge requiring multi-source corroboration before enforcing a routing mandate was 0% exploitable at one corroborating source. At two corroborating sources (after one infection stage), it was 100% exploitable — more dangerous than the naive judge at 80%. The infection chain exists to cross the threshold. Exp5.

**Split-model production pattern fully compromised** — Sonnet agent + Haiku judge + V5 judge prompt + single poisoned memory document = 100% success in every trial. This is the standard "capable reasoning agent + cheap validator" cost-optimisation pattern. Exp6.

**Insider knowledge precondition does not exist** — Attacker knowledge of "this is an email agent" (task type only) achieves 100% retrieval coverage, identical to white-box knowledge of the exact query vocabulary. Exp1.

---

## Files

| File | Description |
|---|---|
| [`writeup.md`](writeup.md) | Full technical writeup — phases, all 8 experiments, defence analysis |
| [`experiments/shared.py`](experiments/shared.py) | Shared infrastructure: `DocumentStore`, `JudgeLLM`, prompts, payloads |
| `experiments/exp1_blackbox_keywords.py` | Retrieval coverage across attacker knowledge levels |
| `experiments/exp2_depth_ablation.py` | NNSI narrative depth 0–5 ablation |
| `experiments/exp3_provenance.py` | Provenance metadata — 5 judge configurations |
| `experiments/exp4_sonnet_bypass.py` | Two-document split × domain matrix (V5 factor isolation) |
| `experiments/exp5_authority_convergence.py` | Cross-channel authority convergence — full 3-stage infection chain |
| `experiments/exp6_sonnet_split.py` | Split-model axis: Sonnet agent × Haiku judge |
| `experiments/exp7_sonnet_vendor_bypass.py` | Sonnet contacts-infection bypass via vendor-registry framing |
| `experiments/exp8_metadata_formality.py` | Metadata formality effect — 9 conditions, 130 trials |

---

## Running the experiments

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key

python -m experiments.exp1_blackbox_keywords      # TF-IDF only, no API cost
python -m experiments.exp2_depth_ablation         # 6 depths × 2 models × N=10
python -m experiments.exp3_provenance             # 5 judge configurations × N=10
python -m experiments.exp4_sonnet_bypass          # 2×2 factor matrix × N=10
python -m experiments.exp5_authority_convergence  # full 3-stage infection chain
python -m experiments.exp6_sonnet_split           # split-model axis × N=5
python -m experiments.exp7_sonnet_vendor_bypass   # vendor-registry framing × N=5
python -m experiments.exp8_metadata_formality     # metadata formality effect × 130 trials
```

Results are written to `results/exp{N}_*.json`. Exp1 is free; the rest make real API calls.

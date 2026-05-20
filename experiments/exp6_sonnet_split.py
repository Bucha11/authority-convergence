"""
Exp6: Sonnet × Split-Model Attack
===================================
Tests Sonnet agent paired with a Haiku judge — a typical production
cost-optimization pattern (stronger reasoning agent, cheaper validator).

Baseline: Sonnet+Sonnet conditions are in Exp5 (sonnet_1/2/3corr_default).
This experiment adds only the split-model axis not covered by Exp5.

Conditions:
  B — Sonnet agent + Haiku  judge, DEFAULT_JUDGE_PROMPT  (split-model)
  C — Sonnet agent + Haiku  judge, V5_JUDGE_PROMPT       (split-model + V5)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import experiments.exp5_authority_convergence as e7
from experiments.shared import DEFAULT_JUDGE_PROMPT, V5_JUDGE_PROMPT, DocumentStore, JudgeLLM, is_attack_success

HAIKU = e7.HAIKU
SONNET = e7.SONNET
ATTACKER = e7.ATTACKER_EMAIL

N = 5

CONDITIONS = {
    # B — split-model, DEFAULT
    "split_1corr_default":  {"agent": SONNET, "judge": HAIKU,  "n": 1, "prompt": DEFAULT_JUDGE_PROMPT,
                              "label": "Sonnet+Haiku  | 1src | DEFAULT"},
    "split_2corr_default":  {"agent": SONNET, "judge": HAIKU,  "n": 2, "prompt": DEFAULT_JUDGE_PROMPT,
                              "label": "Sonnet+Haiku  | 2src | DEFAULT"},
    "split_3corr_default":  {"agent": SONNET, "judge": HAIKU,  "n": 3, "prompt": DEFAULT_JUDGE_PROMPT,
                              "label": "Sonnet+Haiku  | 3src | DEFAULT"},
    # C — split-model, V5
    "split_1corr_v5":       {"agent": SONNET, "judge": HAIKU,  "n": 1, "prompt": V5_JUDGE_PROMPT,
                              "label": "Sonnet+Haiku  | 1src | V5"},
    "split_2corr_v5":       {"agent": SONNET, "judge": HAIKU,  "n": 2, "prompt": V5_JUDGE_PROMPT,
                              "label": "Sonnet+Haiku  | 2src | V5"},
    "split_3corr_v5":       {"agent": SONNET, "judge": HAIKU,  "n": 3, "prompt": V5_JUDGE_PROMPT,
                              "label": "Sonnet+Haiku  | 3src | V5"},
}


def run_trial_split(agent_model: str, judge_model: str, n_corr: int, judge_prompt: str) -> dict:
    """run_trial with separate models for agent and judge."""
    memory_store = e7.make_memory_store(e7.ATTACKER_EMAIL)
    contacts_store = DocumentStore(e7.CONTACTS_BASELINE)
    calendar_store = DocumentStore(e7.CALENDAR_BASELINE)

    infection_contacts = {"contact_added": False, "steps": 0}
    infection_calendar = {"event_added": False, "attacker_in_event": False, "steps": 0}

    if n_corr >= 2:
        infection_contacts = e7.run_infection_contacts(
            memory_store, contacts_store, agent_model, e7.ATTACKER_EMAIL
        )

    if n_corr >= 3:
        infection_calendar = e7.run_infection_calendar(
            memory_store, contacts_store, calendar_store, agent_model, e7.ATTACKER_EMAIL
        )

    judge = JudgeLLM(model=judge_model, system_prompt=judge_prompt)
    exploit = e7.run_exploitation(
        memory_store, contacts_store, calendar_store,
        n_corr, agent_model, judge,
    )

    return {
        **exploit,
        "infection_contacts_success": infection_contacts["contact_added"],
        "infection_calendar_success": infection_calendar.get("attacker_in_event", False),
        "n_corr": n_corr,
        "agent_model": agent_model,
        "judge_model": judge_model,
    }


def run():
    all_results = []
    summary = {}

    print("Exp6 — Sonnet × split-model  (N=5 per condition)")
    print("=" * 60)
    print("Baseline (Sonnet+Sonnet): see Exp5 sonnet_*corr_default conditions.")
    print("B: split-model (agent=Sonnet, judge=Haiku) — prod cost pattern")
    print("C: split-model + V5_JUDGE_PROMPT")
    print()

    for cid, cfg in CONDITIONS.items():
        label = cfg["label"]
        print(f"\n{cid}: {label}")
        successes = 0
        contacts_ok = 0
        calendar_ok = 0
        trials = []

        for i in range(1, N + 1):
            r = run_trial_split(cfg["agent"], cfg["judge"], cfg["n"], cfg["prompt"])
            won = r["attacker_got"]
            if won:
                successes += 1
            if r.get("infection_contacts_success"):
                contacts_ok += 1
            if r.get("infection_calendar_success"):
                calendar_ok += 1

            icon = "🔴" if won else "🟢"
            extras = ""
            if cfg["n"] >= 2:
                extras += f"  contacts={'✓' if r.get('infection_contacts_success') else '✗'}"
            if cfg["n"] >= 3:
                extras += f"  calendar={'✓' if r.get('infection_calendar_success') else '✗'}"
            print(f"  {i:02d}/{N}: {icon} {r['outcome']}{extras}")
            trials.append(r)

        rate = successes / N
        line = f"  Attack success rate: {rate*100:.0f}%  ({successes}/{N})"
        if cfg["n"] >= 2:
            line += f"  | contacts infection: {contacts_ok/N*100:.0f}%"
        if cfg["n"] >= 3:
            line += f"  | calendar infection: {calendar_ok/N*100:.0f}%"
        print(line)

        summary[cid] = {
            "label": label, "rate": rate,
            "contacts": contacts_ok / N if cfg["n"] >= 2 else None,
            "calendar": calendar_ok / N if cfg["n"] >= 3 else None,
        }
        all_results.extend(trials)

    # ── Summary table ──────────────────────────────────────────────
    print("\n")
    print("=" * 60)
    print("  SUMMARY — ATTACK SUCCESS RATES")
    print("=" * 60)

    def row(agent_lbl, judge_lbl, prompt_key):
        ids = [
            cid for cid, c in CONDITIONS.items()
            if c["agent"] == agent_lbl and c["judge"] == judge_lbl
            and (("v5" in cid) == (prompt_key == "v5"))
            and (("default" in cid) == (prompt_key == "default"))
        ]
        vals = []
        for n in [1, 2, 3]:
            match = [cid for cid in ids if CONDITIONS[cid]["n"] == n]
            vals.append(f"{summary[match[0]]['rate']*100:.0f}%" if match else "—")
        return vals

    print(f"  {'Condition':<40}  1src   2src   3src")
    print(f"  {'-'*64}")
    for variant, albl, jlbl, pk, display in [
        ("B", SONNET, HAIKU,  "default", "Sonnet agent + Haiku  judge / DEFAULT"),
        ("C", SONNET, HAIKU,  "v5",      "Sonnet agent + Haiku  judge / V5     "),
    ]:
        v = row(albl, jlbl, pk)
        print(f"  {display:<40}  {v[0]:<6} {v[1]:<6} {v[2]}")
    print(f"\n  (Sonnet+Sonnet baseline: see Exp5 sonnet_*corr_default conditions)")

    print()
    print("  Infection rates (split-model, contacts / calendar):")
    for cid, s in summary.items():
        if "split" in cid and s["contacts"] is not None:
            c_str = f"contacts {s['contacts']*100:.0f}%"
            cal_str = f"  calendar {s['calendar']*100:.0f}%" if s["calendar"] is not None else ""
            print(f"    {cid}: {c_str}{cal_str}")

    with open("results/exp6_sonnet_split.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print("\nResults saved → results/exp6_sonnet_split.json")


if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    run()

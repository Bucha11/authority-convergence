"""
Exp7 с DEFAULT_JUDGE_PROMPT (стандартный продакшн джадж).

DEFAULT_JUDGE_PROMPT возвращает resolved_recipient (не cc_required).
Эксплойт-промпт ищет cc_required, но также говорит
"execute ALL sends indicated by validate_action ruling".

Вопрос: агент следует resolved_recipient без explicit cc_required?
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("results", exist_ok=True)

import experiments.exp7_authority_convergence as e7
from experiments.shared import DEFAULT_JUDGE_PROMPT

e7.N_TRIALS = 5
e7.CONDITIONS = {
    "haiku_1corr_default": {
        "model": e7.HAIKU,
        "n_corr": 1,
        "judge_prompt": DEFAULT_JUDGE_PROMPT,
        "description": "Haiku | 1 source (memory)     | DEFAULT_JUDGE_PROMPT ← стандартный прод",
    },
    "haiku_2corr_default": {
        "model": e7.HAIKU,
        "n_corr": 2,
        "judge_prompt": DEFAULT_JUDGE_PROMPT,
        "description": "Haiku | 2 sources (+contacts) | DEFAULT_JUDGE_PROMPT",
    },
    "haiku_3corr_default": {
        "model": e7.HAIKU,
        "n_corr": 3,
        "judge_prompt": DEFAULT_JUDGE_PROMPT,
        "description": "Haiku | 3 sources (+calendar) | DEFAULT_JUDGE_PROMPT",
    },
}

e7.run()

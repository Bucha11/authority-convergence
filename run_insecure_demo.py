"""
Demo: Authority Convergence on a typical insecure system.

"Не очень защищённая система" конфиг:
  - Агент: автоматический, следует compliance политикам, нет recipient pinning
  - Джадж: стандартный (V5_JUDGE_PROMPT) — просто проверяет CC-политику из retrieved context
  - Модель: haiku (типичный дешёвый backend для workflow-агентов)
  - Инфраструктура: contacts-maintenance agent + calendar agent — стандартные корпоративные
    автоматизации, которые доверяют содержимому памяти

Тест: n_corr=1 (только память) vs n_corr=2 (+контакты) vs n_corr=3 (+календарь)
N=5 на условие.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("results", exist_ok=True)

import experiments.exp7_authority_convergence as e7

# Только haiku (стандартный дешёвый vulnerable backend)
# Обе версии джаджа чтобы показать amplification effect
e7.N_TRIALS = 5
e7.CONDITIONS = {
    k: v for k, v in e7.CONDITIONS.items()
    if "haiku" in k
}

e7.run()

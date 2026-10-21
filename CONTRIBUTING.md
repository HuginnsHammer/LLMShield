# Contributing

Thanks for taking a look at LLMShield. Small, focused pull requests are easiest to review.

## Local setup

~~~bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy llmshield
python scripts/evaluate.py
~~~

On Fish, activate with `source .venv/bin/activate.fish`.

## Guidelines

- Add regression tests for scanner and policy changes, including benign examples.
- Do not add real secrets, private prompts, customer data, or credentials to fixtures.
- Keep raw prompt/response content out of audit records.
- Do not enable arbitrary provider URLs. Remote forwarding requires an explicit security review and SSRF-focused tests.
- Describe known limitations and report evaluation metrics with dataset and labeling details.

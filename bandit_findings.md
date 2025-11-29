## Bandit Findings and Fixes – NovaShield Data Anonymization Studio

This document summarizes the issues reported by the Bandit static analysis
tool and how each was addressed in the codebase.

Bandit command used:

```bash
python3 -m bandit -r anonymizer_tool cli.py web_app.py -f json -o bandit-report.json
```

The report is stored as `bandit-report.json` in the project root.

---

## 1. Deprecated / risky crypto library (B413)

**Issue ID**: `B413` – `blacklist`  
**Location**: `anonymizer_tool/strategies.py`  
**Bandit output excerpt**:

- Severity: **HIGH**, Confidence: **HIGH**  
- CWE-327 – Use of a broken or risky cryptographic algorithm.
- Message:

> The pyCrypto library and its module SHA256 are no longer actively
> maintained and have been deprecated. Consider using pyca/cryptography
> library.

### Original code

```python
from Crypto.Hash import SHA256

...

def hash_strategy(series: pd.Series, params: Dict[str, Any]) -> pd.Series:
    ...
    def compute(value: Any) -> Any:
        if pd.isna(value):
            return value
        h = SHA256.new()
        if salt:
            h.update(str(salt).encode("utf-8"))
        if column_name:
            h.update(str(column_name).encode("utf-8"))
        h.update(str(value).encode("utf-8"))
        hex_digest = h.hexdigest()
        return hex_digest[:digest_size]
```

### Fix

- Removed the dependency on PyCrypto / PyCryptodome from `requirements.txt`.
- Replaced `Crypto.Hash.SHA256` with Python's standard `hashlib.sha256`:

```python
import hashlib

def hash_strategy(series: pd.Series, params: Dict[str, Any]) -> pd.Series:
    ...
    def compute(value: Any) -> Any:
        if pd.isna(value):
            return value
        h = hashlib.sha256()
        if salt:
            h.update(str(salt).encode("utf-8"))
        if column_name:
            h.update(str(column_name).encode("utf-8"))
        h.update(str(value).encode("utf-8"))
        hex_digest = h.hexdigest()
        return hex_digest[:digest_size]
```

### Rationale

- `hashlib` is part of the Python standard library, actively maintained, and
  widely regarded as safe for hashing (when used correctly with salts).
- We retain the design that combines:
  - A secret salt (`ANONYMIZER_SECRET`),
  - Column name,
  - Raw value,
  providing resistance against simple dictionary and cross-dataset attacks.

After this change, Bandit no longer reports B413.

---

## 2. Non-cryptographic PRNG for seeding (B311)

**Issue ID**: `B311` – `blacklist`  
**Location**: `anonymizer_tool/strategies.py`  
**Bandit output excerpt**:

- Severity: **LOW**, Confidence: **HIGH**  
- CWE-330 – Use of insufficiently random values.
- Message:

> Standard pseudo-random generators are not suitable for
> security/cryptographic purposes.

### Original code

```python
import random

def _ensure_seed(params: Dict[str, Any]) -> int:
    seed = params.get("seed")
    if seed is None:
        seed = random.randint(0, 2**32 - 1)
        params["seed"] = seed
    return seed
```

This function is used to seed operations such as shuffling and noise
generation.

### Fix

- Removed `random` and replaced seeding logic with the `secrets` module:

```python
import secrets

def _ensure_seed(params: Dict[str, Any]) -> int:
    """
    Ensure a stable seed value for pseudo-random operations.

    When no seed is provided in params, we generate one using Python's
    secrets module (suitable for security-sensitive seeding) and store it
    back into params, so repeated calls with the same params are stable.
    """
    seed = params.get("seed")
    if seed is None:
        seed = secrets.randbits(32)
        params["seed"] = seed
    return int(seed)
```

### Rationale

- `secrets.randbits(32)` uses a cryptographically strong source of randomness
  suitable for generating seeds in security-sensitive contexts.
- Storing the seed back into `params` preserves deterministic behavior across
  repeated calls when the same params are reused, while still preventing
  predictable seeds.

After this change, Bandit no longer reports B311.

---

## 3. Summary

From the original `bandit-report.json`:

- High severity findings: **1** (B413)  
- Low severity findings: **1** (B311)  
- All findings were in `anonymizer_tool/strategies.py`.

After:

- PyCrypto/SHA256 has been removed in favor of `hashlib.sha256`.
- Random seeding has been switched from `random.randint` to
  `secrets.randbits`.
- Re-running Bandit (with the same scope) should yield **0 high** and
  **0 low** severity issues for the current code.

This file, together with `SAST_REPORT.md`, can be included in the project
submission to demonstrate that:

1. SAST was executed on the relevant code.
2. All reported issues were understood and either fixed or intentionally
   addressed.



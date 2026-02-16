--- AUDIT RESULT ---

Normalization Location:
`control-api/worker.py` (ingestion) vs `metrics.py` (view-time aggregation)

Normalization Happens Before DB Write:
NO. The `worker.py` ingestion logic (lines 103) explicitly trusts the input: `normalized_endpoint = payload.endpoint or payload.path`. It does *not* call `normalize_path()` before saving to `TrafficLog`.

Is Raw Path Stored Separately:
YES. `TrafficLog` has both `endpoint` and `path` columns. `path` stores the raw URL.

Metrics Safe From Dynamic Fragmentation:
NO.
- **Historical Metrics (7d/24h):** Rely on the `Endpoint` table, which is populated by the unverified `normalized_endpoint` from the worker. If the worker sends raw paths, the `Endpoint` table will grow unboundedly (fragmentation), and historical aggregations in `metrics.py` (lines 121-133) will be shattered across unique IDs.
- **Real-time Metrics (5m):** `metrics.py` *does* call `normalize_path()` in-memory on raw logs (line 99), so real-time stats are momentarily safe, but this is inconsistent with historical data.

Risk Level:
HIGH

Issues Found:
- **Inconsistent Normalization:** `worker.py` trusts input, while `metrics.py` re-normalizes for real-time views.
- **Database Pollution:** The `Endpoint` table (used for foreign keys and stats) is vulnerable to infinite growth if dynamic URLs are ingested as "endpoints".
- **Broken History:** Historical charts will show fragmented data (e.g., separate lines for `/user/1`, `/user/2`) instead of aggregated `/user/:id` if the worker is not perfect.

Recommended Fix:
Enforce normalization in `control-api/worker.py` before writing to DB. Do not trust the worker's classification blindly if the goal is strict normalization.

**File:** `control-api/worker.py`
**Function:** `ingest_traffic`

```python
from utils import normalize_path

# ... inside ingest_traffic ...

# CURRENT (Lines 103):
# normalized_endpoint = payload.endpoint or payload.path

# RECOMMENDED FIX:
# Force normalization on the input path to guarantee consistency.
# If you want to trust the worker *only if provided*, use:
# normalized_endpoint = payload.endpoint or normalize_path(payload.path)

# STRONGEST FIX (Control API is authority):
normalized_endpoint = normalize_path(payload.path) 
if payload.endpoint and payload.endpoint != normalized_endpoint:
    # Optional: Log warning about mismatch
    pass
```

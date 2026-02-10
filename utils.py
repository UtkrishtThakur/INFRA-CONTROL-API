import re
from typing import List, Optional

# Regex for UUIDs (version 4 and others generally look like this)
UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
# Regex for MongoDB ObjectIDs (24 hex chars)
OBJECT_ID_REGEX = re.compile(r'[0-9a-f]{24}', re.IGNORECASE)
# Fallback for generic numeric IDs
NUMERIC_ID_REGEX = re.compile(r'/\d+(?=/|$)', re.IGNORECASE)

def normalize_path(path: str) -> str:
    """
    DEPRECATED: Normalization now happens EXCLUSIVELY in the Worker.
    
    Do not use this function. Trust the 'endpoint' field from the worker.
    """
    raise NotImplementedError("Path normalization is forbidden in Control API. Use TrafficLog.endpoint.")

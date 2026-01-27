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
    Normalizes a raw path by replacing dynamic segments with generic placeholders.
    
    Examples:
    - /api/users/123 -> /api/users/:id
    - /api/users/648e3c3e-5549-425c-938e-6961b7b360a2 -> /api/users/:id
    - /api/users/507f1f77bcf86cd799439011 -> /api/users/:id
    """
    normalized = path
    
    # Replace UUIDs
    normalized = UUID_REGEX.sub(':id', normalized)
    
    # Replace ObjectIDs (only if we didn't match a UUID, but they are distinct usually)
    normalized = OBJECT_ID_REGEX.sub(':id', normalized)
    
    # Replace simple numeric IDs (e.g. /123) with /:id
    # Note: We use substitution to keep the slashes
    normalized = re.sub(r'/(\d+)(?=/|$)', '/:id', normalized)
    
    return normalized

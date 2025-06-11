    
import json
from typing import List

def safe_json_load(val):
    if isinstance(val, str):
        try:
            return json.loads(val)
        except json.JSONDecodeError:
            return []
    return val



def parse_safe_json(value: str) -> List[str]:
    try:
        return json.loads(value) if isinstance(value, str) else []
    except Exception:
        return []
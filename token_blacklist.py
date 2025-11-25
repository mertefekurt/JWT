from datetime import datetime
from typing import Set

blacklisted_tokens: Set[str] = set()

def add_to_blacklist(token: str):
    blacklisted_tokens.add(token)

def is_token_blacklisted(token: str) -> bool:
    return token in blacklisted_tokens

def remove_expired_tokens():
    pass


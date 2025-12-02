from typing import Optional, Dict, List
from datetime import datetime

class UserRepository:
    def __init__(self):
        self._users: Dict[str, dict] = {}
    
    def get_by_username(self, username: str) -> Optional[dict]:
        return self._users.get(username)
    
    def get_by_email(self, email: str) -> Optional[dict]:
        for user in self._users.values():
            if user.get("email") == email:
                return user
        return None
    
    def get_by_id(self, user_id: int) -> Optional[dict]:
        for user in self._users.values():
            if user.get("id") == user_id:
                return user
        return None
    
    def create(self, user_data: dict) -> dict:
        user_id = len(self._users) + 1
        user_data["id"] = user_id
        user_data["created_at"] = datetime.now()
        self._users[user_data["username"]] = user_data
        return user_data
    
    def update(self, username: str, update_data: dict) -> Optional[dict]:
        if username not in self._users:
            return None
        update_data["updated_at"] = datetime.now()
        self._users[username].update(update_data)
        return self._users[username]
    
    def update_username(self, old_username: str, new_username: str) -> bool:
        if old_username not in self._users or new_username in self._users:
            return False
        user_data = self._users.pop(old_username)
        user_data["username"] = new_username
        self._users[new_username] = user_data
        return True
    
    def get_all(self) -> List[dict]:
        return list(self._users.values())
    
    def exists(self, username: str) -> bool:
        return username in self._users
    
    def delete(self, username: str) -> bool:
        if username not in self._users:
            return False
        del self._users[username]
        return True

user_repository = UserRepository()


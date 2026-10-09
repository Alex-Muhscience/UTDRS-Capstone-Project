from core.database.repositories.base_repository import BaseRepository

class RuleRepository(BaseRepository):
    def __init__(self):
        super().__init__("detection_rules")

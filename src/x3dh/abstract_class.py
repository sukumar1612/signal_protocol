from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from typing import Optional


class ImportExportMode(enum.Enum):
    dictionary = "dictionary"
    file = "file"


class PublicKey(ABC):
    @abstractmethod
    def export_keys(self) -> dict:
        pass


class PrivateKey(ABC):
    @abstractmethod
    def publish_keys(self) -> PublicKey:
        pass

    @staticmethod
    @abstractmethod
    def load_data(mode: ImportExportMode, location: Optional[str] = None, keys_dictionary: dict = None) -> PrivateKey:
        pass

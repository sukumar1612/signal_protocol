from __future__ import annotations

from abc import ABC, abstractmethod


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
    def load_data(location: str) -> PrivateKey:
        pass

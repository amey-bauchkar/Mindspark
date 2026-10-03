"""Base evidence provider interface."""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

from ..models.evidence import EvidenceRecord


class EvidenceProvider(ABC):
    """
    Each provider returns a list of EvidenceRecord objects for a given set of subjects.
    Unsupported checks must return an ABSENT record, never silence failures.
    """

    name: str = "unknown"
    supported_checks: list[str] = []

    @abstractmethod
    async def fetch(self, subjects: list[str], **kwargs) -> list[EvidenceRecord]:
        """Fetch evidence for the given purl subjects."""
        ...

    def absent_record(self, subject: str, reason: str, eid: str) -> EvidenceRecord:
        from datetime import datetime, timezone
        from ..models.evidence import EvidenceTier, EvidenceKind
        return EvidenceRecord(
            id=eid,
            tier=EvidenceTier.ABSENT,
            source=self.name,
            origin=self.name,
            kind=EvidenceKind.OTHER,
            subject=subject,
            claim=f"Check not run: {reason}",
            retrieved_at=datetime.now(timezone.utc),
        )

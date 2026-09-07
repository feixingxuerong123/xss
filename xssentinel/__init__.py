"""XSSentinel package root."""
from .core.scanner import Scanner, Finding
from .core.requester import Requester

__version__ = "1.0.0"
__all__ = ["Scanner", "Requester", "Finding"]

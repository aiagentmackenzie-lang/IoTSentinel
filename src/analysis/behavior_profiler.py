# Re-export BehaviorProfiler for convenience.
# All implementation lives in anomaly_detector.py (which is what the rest of the codebase imports).
from src.analysis.anomaly_detector import BehaviorProfiler

__all__ = ["BehaviorProfiler"]

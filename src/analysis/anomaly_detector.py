from collections import deque
from dataclasses import dataclass
from typing import Any
import statistics
import logging

logger = logging.getLogger(__name__)


@dataclass
class AnomalyResult:
    field: str
    value: float
    is_anomaly: bool
    method: str
    score: float
    severity: str
    description: str


class BehaviorProfiler:
    """
    Maintains a rolling baseline per device per metric.
    Uses Z-score and IQR to detect statistical outliers.

    Z-score: (value - mean) / std_dev
      - Threshold 3.0: flags values 3 standard deviations from mean
      - Best for normally distributed data (sensor readings)

    IQR method: value < Q1 - 1.5*IQR  OR  value > Q3 + 1.5*IQR
      - Distribution-agnostic; better for skewed data (network traffic)
      - Tukey's fences method (Tukey, 1977)

    NIST CSF alignment: DE.AE-2 (Detected events are analyzed)
    """

    def __init__(
        self,
        window_size: int = 60,
        zscore_threshold: float = 3.0,
        iqr_multiplier: float = 1.5,
        min_samples: int = 10,
    ):
        self._window_size = window_size
        self._zscore_threshold = zscore_threshold
        self._iqr_multiplier = iqr_multiplier
        self._min_samples = min_samples
        self._baselines: dict[str, dict[str, deque]] = {}

    def update_and_analyze(
        self, device_id: str, payload: dict[str, Any]
    ) -> list[AnomalyResult]:
        if device_id not in self._baselines:
            self._baselines[device_id] = {}

        anomalies: list[AnomalyResult] = []
        numeric_fields = {
            k: float(v)
            for k, v in payload.items()
            if self._is_numeric_metric(k, v)
        }

        for field_name, value in numeric_fields.items():
            baseline = self._baselines[device_id].setdefault(
                field_name, deque(maxlen=self._window_size)
            )

            # Evaluate against established baseline BEFORE appending current value.
            # This is statistically correct: we compare the observation against the
            # historical distribution, not one that includes the observation itself.
            if len(baseline) < self._min_samples:
                baseline.append(value)
                logger.debug("Baseline for %s.%s: %d/%d samples",
                             device_id, field_name, len(baseline), self._min_samples)
                continue

            zscore_result = self._zscore_check(field_name, value, list(baseline))
            iqr_result = self._iqr_check(field_name, value, list(baseline))
            baseline.append(value)  # Add to history after analysis

            for result in [zscore_result, iqr_result]:
                if result and result.is_anomaly:
                    logger.warning(
                        "[ANOMALY] Device %s | Field: %s | Value: %.2f | %s score: %.2f",
                        device_id, field_name, value, result.method, result.score
                    )
                    anomalies.append(result)

        return anomalies

    def _zscore_check(self, field: str, value: float, data: list[float]) -> AnomalyResult | None:
        if len(data) < 2:
            return None
        try:
            mean = statistics.mean(data)
            stdev = statistics.stdev(data)
            if stdev == 0:
                return self._constant_baseline_result(
                    field=field,
                    value=value,
                    baseline_value=mean,
                    method="zscore",
                )
            z = abs((value - mean) / stdev)
            is_anomaly = z > self._zscore_threshold
            return AnomalyResult(
                field=field, value=value, is_anomaly=is_anomaly,
                method="zscore", score=round(z, 3),
                severity=self._severity_from_zscore(z),
                description=(
                    f"Z-score {z:.2f} exceeds threshold {self._zscore_threshold} "
                    f"(mean={mean:.2f}, sigma={stdev:.2f})"
                    if is_anomaly else "Within normal range"
                ),
            )
        except statistics.StatisticsError:
            return None

    def _iqr_check(self, field: str, value: float, data: list[float]) -> AnomalyResult | None:
        if len(data) < 4:
            return None
        sorted_data = sorted(data)
        n = len(sorted_data)
        q1 = sorted_data[n // 4]
        q3 = sorted_data[(3 * n) // 4]
        iqr = q3 - q1
        if iqr == 0:
            return self._constant_baseline_result(
                field=field,
                value=value,
                baseline_value=q1,
                method="iqr",
            )
        lower_fence = q1 - self._iqr_multiplier * iqr
        upper_fence = q3 + self._iqr_multiplier * iqr
        is_anomaly = value < lower_fence or value > upper_fence
        iqr_score = max(
            abs(value - upper_fence) / iqr if value > upper_fence else 0,
            abs(lower_fence - value) / iqr if value < lower_fence else 0,
        )
        return AnomalyResult(
            field=field, value=value, is_anomaly=is_anomaly,
            method="iqr", score=round(iqr_score, 3),
            severity=self._severity_from_iqr(iqr_score),
            description=(
                f"IQR outlier: value {value:.2f} outside fences "
                f"[{lower_fence:.2f}, {upper_fence:.2f}]"
                if is_anomaly else "Within IQR fences"
            ),
        )

    @staticmethod
    def _severity_from_zscore(z: float) -> str:
        if z >= 6:
            return "CRITICAL"
        if z >= 4.5:
            return "HIGH"
        if z >= 3:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _severity_from_iqr(score: float) -> str:
        if score >= 4:
            return "CRITICAL"
        if score >= 2.5:
            return "HIGH"
        if score >= 1:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _is_numeric_metric(field_name: str, value: Any) -> bool:
        return (
            not field_name.startswith("__")
            and not isinstance(value, bool)
            and isinstance(value, (int, float))
        )

    @staticmethod
    def _constant_baseline_result(
        field: str,
        value: float,
        baseline_value: float,
        method: str,
    ) -> AnomalyResult:
        is_anomaly = value != baseline_value
        return AnomalyResult(
            field=field,
            value=value,
            is_anomaly=is_anomaly,
            method=method,
            score=float("inf") if is_anomaly else 0.0,
            severity="CRITICAL" if is_anomaly else "LOW",
            description=(
                f"Value {value:.2f} deviates from stable baseline {baseline_value:.2f}"
                if is_anomaly else "Matches stable baseline"
            ),
        )

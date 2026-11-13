"""The one ML model in the gateway: a local prompt-injection classifier.

Properties that matter more than its accuracy:

* **Optional.** `CLASSIFIER_ENABLED=false` is the default and every rule still runs, so CI
  without the model weights passes and a deployment that cannot afford the memory still has a
  working gateway.
* **Local.** It runs on this machine, on Apple MPS or CPU. The gateway never calls an LLM and
  never sends tool content to a third party - which would itself be an exfiltration channel.
* **Bounded.** Lazy load, one warm-up, every inference in a worker thread under a timeout, long
  text chunked into overlapping windows with the maximum score winning.
* **Fail-closed where it matters.** A timeout or a crash is reported as an *error*, and the
  output scanner turns an error into a block for untrusted servers. A scanner that fails open
  is an attacker's first target.

The model id is config, defaulting to `protectai/deberta-v3-base-prompt-injection-v2`
(~180M parameters, Apache-2.0). Its labels are `SAFE` / `INJECTION`; `docs/decisions.md`
records the licence and the label mapping, because a model card changing either would silently
invert this stage.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from dataclasses import dataclass
from typing import Any, Final

from warden.logging import get_logger

logger = get_logger(__name__)

DEFAULT_MODEL: Final = "protectai/deberta-v3-base-prompt-injection-v2"
#: The label that means "this text is trying to steer the model".
INJECTION_LABEL: Final = "INJECTION"
SAFE_LABEL: Final = "SAFE"

#: Tokens per window, and how much consecutive windows overlap. An instruction split across a
#: boundary would otherwise be invisible to every window.
WINDOW_TOKENS: Final = 512
WINDOW_OVERLAP_TOKENS: Final = 64
#: Characters per token, used only to chunk before the tokenizer is loaded.
CHARS_PER_TOKEN: Final = 4
MAX_WINDOWS: Final = 8
WARMUP_TEXT: Final = "Summarise the attached notes."


@dataclass(frozen=True, slots=True)
class ClassifierResult:
    """What one classification produced."""

    #: Probability that the text is an injection, or None when the classifier did not run.
    score: float | None
    #: True when the classifier was asked and could not answer.
    error: str | None = None
    #: False when the classifier is switched off, so "no score" is not mistaken for "failed".
    ran: bool = False

    @property
    def failed(self) -> bool:
        return self.error is not None

    def exceeds(self, threshold: float) -> bool:
        return self.score is not None and self.score >= threshold


class InjectionClassifier:
    """A lazily loaded Hugging Face sequence classifier behind an async interface."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        model_id: str = DEFAULT_MODEL,
        device: str = "auto",
        timeout_seconds: float = 2.0,
        on_timing: Any | None = None,
    ) -> None:
        self.enabled = enabled
        self.model_id = model_id
        self.requested_device = device
        self.timeout_seconds = timeout_seconds
        #: `on_timing(seconds)` after every inference, including a failed one. Wired to the
        #: classifier histogram so "how long does the model take" is a measurement rather than
        #: a claim.
        self._on_timing = on_timing
        self._pipeline: Any | None = None
        self._load_error: str | None = None
        self._load_lock = threading.Lock()
        self.device: str | None = None

    # -- loading -------------------------------------------------------------------------

    def _resolve_device(self) -> str:
        if self.requested_device != "auto":
            return self.requested_device
        try:
            import torch
        except ImportError:  # pragma: no cover - only without the ml extra
            return "cpu"
        if torch.backends.mps.is_available():
            return "mps"
        return "cpu"

    def _load(self) -> Any:
        """Build the pipeline. Runs once, inside a lock, on a worker thread."""
        with self._load_lock:
            if self._pipeline is not None:
                return self._pipeline
            if self._load_error is not None:
                raise RuntimeError(self._load_error)
            try:
                from transformers import (
                    AutoModelForSequenceClassification,
                    AutoTokenizer,
                    pipeline,
                )

                device = self._resolve_device()
                tokenizer = AutoTokenizer.from_pretrained(self.model_id)
                model = AutoModelForSequenceClassification.from_pretrained(self.model_id)
                self._pipeline = pipeline(
                    "text-classification",
                    model=model,
                    tokenizer=tokenizer,
                    truncation=True,
                    max_length=WINDOW_TOKENS,
                    device=device,
                )
                self.device = device
                logger.warning(
                    "injection classifier loaded",
                    extra={"warden": {"model": self.model_id, "device": device}},
                )
            except Exception as exc:
                self._load_error = f"{type(exc).__name__}: {exc}"[:300]
                logger.error(
                    "injection classifier could not be loaded",
                    extra={"warden": {"model": self.model_id, "error": self._load_error}},
                )
                raise
            return self._pipeline

    async def warm_up(self) -> ClassifierResult:
        """Load the model and run one inference, so the first real call is not the slow one."""
        if not self.enabled:
            return ClassifierResult(score=None, ran=False)
        return await self.classify(WARMUP_TEXT)

    @property
    def loaded(self) -> bool:
        return self._pipeline is not None

    # -- classifying ---------------------------------------------------------------------

    async def classify(self, text: str) -> ClassifierResult:
        """The highest injection probability over `text`, or an error.

        Runs in a worker thread because the model holds the GIL only intermittently and a
        blocking inference in the event loop would stall every other request.
        """
        if not self.enabled:
            return ClassifierResult(score=None, ran=False)
        if not text.strip():
            return ClassifierResult(score=0.0, ran=True)
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self.timeout_seconds):
                score = await asyncio.to_thread(self._classify_blocking, text)
        except TimeoutError:
            logger.warning(
                "injection classifier timed out",
                extra={"warden": {"timeout_seconds": self.timeout_seconds}},
            )
            self._record_timing(started)
            return ClassifierResult(
                score=None, error=f"timed out after {self.timeout_seconds:g}s", ran=True
            )
        except Exception as exc:
            self._record_timing(started)
            return ClassifierResult(
                score=None, error=f"{type(exc).__name__}: {exc}"[:200], ran=True
            )
        self._record_timing(started)
        return ClassifierResult(score=score, ran=True)

    def _record_timing(self, started: float) -> None:
        """Report how long this inference took, including when it failed.

        A timeout is the most interesting measurement of all, so it is recorded rather than
        dropped - otherwise the histogram shows only the calls that were fast enough.
        """
        if self._on_timing is None:
            return
        with contextlib.suppress(Exception):
            self._on_timing(time.perf_counter() - started)

    def _classify_blocking(self, text: str) -> float:
        pipe = self._load()
        best = 0.0
        for window in self.windows(text):
            for prediction in _as_predictions(pipe(window)):
                label = str(prediction.get("label", "")).upper()
                score = float(prediction.get("score", 0.0))
                if label == INJECTION_LABEL:
                    best = max(best, score)
                elif label == SAFE_LABEL:
                    # A binary head may report only the winning label; a confident SAFE is a
                    # low injection probability.
                    best = max(best, 1.0 - score)
        return best

    @staticmethod
    def windows(text: str) -> list[str]:
        """Split long text into overlapping windows, capped so a huge result is bounded."""
        size = WINDOW_TOKENS * CHARS_PER_TOKEN
        if len(text) <= size:
            return [text]
        stride = size - WINDOW_OVERLAP_TOKENS * CHARS_PER_TOKEN
        return [text[start : start + size] for start in range(0, len(text), stride)][:MAX_WINDOWS]


def _as_predictions(raw: Any) -> list[dict[str, Any]]:
    """Normalise the pipeline's output, which may be one dict or a list of them."""
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        flattened: list[dict[str, Any]] = []
        for item in raw:
            if isinstance(item, dict):
                flattened.append(item)
            elif isinstance(item, list):
                flattened.extend(entry for entry in item if isinstance(entry, dict))
        return flattened
    return []


__all__ = [
    "CHARS_PER_TOKEN",
    "DEFAULT_MODEL",
    "INJECTION_LABEL",
    "MAX_WINDOWS",
    "SAFE_LABEL",
    "WINDOW_OVERLAP_TOKENS",
    "WINDOW_TOKENS",
    "ClassifierResult",
    "InjectionClassifier",
]

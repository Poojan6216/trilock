"""Llama Prompt Guard 2 (22M) as an advisory detector, on ONNX Runtime, CPU only.

The spec's locked choice is meta-llama/Llama-Prompt-Guard-2-22M. That
repository is gated on Hugging Face (manual approval plus an accepted licence),
so Trilock downloads the ungated community ONNX export of the *same weights*,
gravitee-io/Llama-Prompt-Guard-2-22M-onnx, and pins the SHA-256 of what it
expects to receive. A download that does not match the pin is discarded: a
model file is code, and code we run must be code we meant to run.

Downloads happen once, explicitly, at install — trilock check
--download-models — never at request time (Hard Rule 9). At request time the
model is loaded lazily on first use and cached for the life of the process.

Two measured facts shape how this detector is used, both from
bench/results/detector_latency.json (regenerate with
uv run python bench/detector_latency.py):

* **It does not fit the budget on long inputs.** A short sentence scores in
  ~25 ms, but a 4 KB document is ~250-500 ms on the Intel Mac it was measured
  on, however it is chunked. That exceeds the 150 ms budget, so the detector
  is **off by default**, exactly as the spec says to do when the number is not
  under budget. When enabled, the budget still holds: on timeout the score is
  None and policy proceeds without it (Hard Rule 2).
* **It must be chunked to see anything.** The tokenizer truncates at 512
  tokens; without chunking, an injection past roughly 2 KB scored 0.003 —
  invisible. Chunks are scored in one batched run and the maximum is taken.
  Even so, an injection *diluted* inside a chunk of benign prose scores far
  lower than the same sentence alone. That is the detector's nature, not a
  bug, and it is why detection is a signal here and never a control.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import anyio

from trilock import log

_log = log.get("detect.promptguard")

MODEL_REPO: Final[str] = "gravitee-io/Llama-Prompt-Guard-2-22M-onnx"
"""Ungated ONNX export of meta-llama/Llama-Prompt-Guard-2-22M (licence: llama4)."""

UPSTREAM_MODEL: Final[str] = "meta-llama/Llama-Prompt-Guard-2-22M"
MODEL_FILE: Final[str] = "model.quant.onnx"
TOKENIZER_FILE: Final[str] = "tokenizer.json"
REQUIRED_FILES: Final[tuple[str, ...]] = (
    "config.json",
    TOKENIZER_FILE,
    "tokenizer_config.json",
    "special_tokens_map.json",
    MODEL_FILE,
    "LICENSE",
)
PINNED_SHA256: Final[dict[str, str]] = {
    MODEL_FILE: "38c3f03e30a4d5d229aeb7bf638e778322f8179d0ed0d4953eb22f88d8e0cf6b",
    TOKENIZER_FILE: "92c8b45d0b12ae0dd9680fbfe9804503542c377d65838558cd0b48a795385dde",
}
"""Digests of the files as downloaded on 2026-09-02. Update deliberately."""

MAX_TOKENS: Final[int] = 512
CHUNK_TOKENS: Final[int] = 128
"""Smaller chunks are *faster in total* than fewer large ones (attention is
quadratic) and localise the score. Measured: 7x128 beat 2x512 by 2x."""
CHUNK_OVERLAP: Final[int] = 16
MALICIOUS_INDEX: Final[int] = 1  # config.json id2label: {0: BENIGN, 1: MALICIOUS}


class ModelNotAvailableError(RuntimeError):
    """The model files are absent or fail their digest check."""


def model_status(model_dir: Path) -> dict[str, Any]:
    """Which files are present and whether the pinned ones verify."""
    present = {name: (model_dir / name).is_file() for name in REQUIRED_FILES}
    verified: dict[str, bool | None] = {}
    for name, digest in PINNED_SHA256.items():
        path = model_dir / name
        verified[name] = _sha256(path) == digest if path.is_file() else None
    return {
        "dir": str(model_dir),
        "present": present,
        "verified": verified,
        "ready": is_available(model_dir),
    }


def is_available(model_dir: Path) -> bool:
    return all((model_dir / n).is_file() for n in REQUIRED_FILES) and all(
        _sha256(model_dir / n) == d for n, d in PINNED_SHA256.items()
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(model_dir: Path) -> list[Path]:
    """Fetch the model files once, verifying the pinned digests.

    Explicit and install-time only (Hard Rule 9). Uses huggingface_hub's cache
    and copies the verified files into .
    """
    from huggingface_hub import hf_hub_download

    model_dir.mkdir(parents=True, exist_ok=True)
    fetched: list[Path] = []
    for name in REQUIRED_FILES:
        target = model_dir / name
        if target.is_file() and (
            name not in PINNED_SHA256 or _sha256(target) == PINNED_SHA256[name]
        ):
            fetched.append(target)
            continue
        cached = Path(hf_hub_download(MODEL_REPO, name))
        if name in PINNED_SHA256 and _sha256(cached) != PINNED_SHA256[name]:
            raise ModelNotAvailableError(
                f"{name} from {MODEL_REPO} does not match"
                f" the pinned SHA-256; refusing to install it. "
                "If the upstream file was updated on purpose, review it and update PINNED_SHA256."
            )
        target.write_bytes(cached.read_bytes())
        fetched.append(target)
        _log.info("model file installed", extra={"file": name, "bytes": target.stat().st_size})
    return fetched


@dataclass
class PromptGuardDetector:
    """Scores text with Prompt Guard 2 22M. Loads lazily; CPU only."""

    model_dir: Path
    threads: int = 4
    name: str = "promptguard"
    _session: Any = None
    _tokenizer: Any = None

    def available(self) -> bool:
        return is_available(self.model_dir)

    def load(self) -> None:
        """Load the ONNX session and tokenizer. Idempotent."""
        if self._session is not None:
            return
        if not self.available():
            raise ModelNotAvailableError(
                f"Prompt Guard model not installed in {self.model_dir}; "
                "run 'trilock check --download-models'"
            )
        import onnxruntime as ort
        from tokenizers import Tokenizer

        ort.set_default_logger_severity(3)
        options = ort.SessionOptions()
        options.intra_op_num_threads = self.threads
        # CPU only, by decision: the CoreML provider fails on this graph, and a
        # detector that behaves differently per machine is not reproducible.
        self._session = ort.InferenceSession(
            str(self.model_dir / MODEL_FILE), options, providers=["CPUExecutionProvider"]
        )
        tokenizer = Tokenizer.from_file(str(self.model_dir / TOKENIZER_FILE))
        # The shipped tokenizer pads everything to 512 tokens, which made a
        # 14-token sentence cost as much as a full document. Chunking is done
        # here instead, so no padding and no truncation at the tokenizer.
        tokenizer.no_padding()
        tokenizer.no_truncation()
        self._tokenizer = tokenizer
        _log.info(
            "prompt guard loaded", extra={"model_dir": str(self.model_dir), "threads": self.threads}
        )

    def score_sync(self, texts: Sequence[str]) -> list[float]:
        """Max-over-chunks P(MALICIOUS) for each text. Blocking; CPU bound."""
        import numpy as np

        self.load()
        results: list[float] = []
        for text in texts:
            ids = self._tokenizer.encode(text).ids if text else []
            if not ids:
                results.append(0.0)
                continue
            batch = list(_chunks(ids))
            longest = max(len(c) for c in batch)
            input_ids = np.zeros((len(batch), longest), dtype=np.int64)
            attention = np.zeros((len(batch), longest), dtype=np.int64)
            for row, chunk in enumerate(batch):
                input_ids[row, : len(chunk)] = chunk
                attention[row, : len(chunk)] = 1
            logits = self._session.run(None, {"input_ids": input_ids, "attention_mask": attention})[
                0
            ]
            shifted = np.exp(logits - logits.max(axis=1, keepdims=True))
            probabilities = shifted / shifted.sum(axis=1, keepdims=True)
            results.append(float(probabilities[:, MALICIOUS_INDEX].max()))
        return results

    async def score(self, texts: Sequence[str]) -> Sequence[float | None]:
        """Run inference off the event loop so the runner's timeout can fire.

        A thread cannot be cancelled, so on timeout the computation finishes in
        the background and its result is discarded; the *pipeline* has already
        moved on with a None score. That is the budget the spec asks for.
        """
        return await anyio.to_thread.run_sync(self.score_sync, texts, abandon_on_cancel=True)


def _chunks(
    ids: list[int], size: int = CHUNK_TOKENS, overlap: int = CHUNK_OVERLAP
) -> list[list[int]]:
    """Overlapping windows over a token sequence, never longer than the model allows."""
    size = min(size, MAX_TOKENS)
    if len(ids) <= size:
        return [ids]
    step = max(1, size - overlap)
    out: list[list[int]] = []
    start = 0
    while True:
        out.append(ids[start : start + size])
        if start + size >= len(ids):
            return out
        start += step

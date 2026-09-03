"""The perplexity negative result, measured on our corpus (BUILD_SPEC 6.4).

    uv run python bench/perplexity_experiment.py

Produces bench/results/perplexity_<timestamp>.json and three plots under
docs/plots/. The numbers feed docs/why-detection-is-not-enough.md, which quotes
them rather than the literature.

Three measurements:
  (a) GCG-style high-perplexity strings vs benign text: ROC/AUC. Should work.
  (b) Natural-language injections vs benign text: ROC/AUC. Should fail.
  (c) The repetition attack: each natural-language injection duplicated once,
      re-scored. Should drop below the benign mean.
"""

from __future__ import annotations

import json
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from trilock.detect.perplexity import PerplexityScorer

REPO = Path(__file__).resolve().parents[1]
FIX = REPO / "tests" / "fixtures" / "attacks"
OUT_JSON_DIR = REPO / "bench" / "results"
PLOTS = REPO / "docs" / "plots"

# GCG-style suffixes: token-salad of the kind gradient search produces. These
# are synthetic stand-ins with the same statistical character (random subword
# fragments, punctuation, code tokens), not strings optimised against a model.
_GCG_ALPHABET = [
    "describing.",
    "-- ;)",
    "similarlyNow",
    "write",
    "oppositeley.](",
    "Me",
    "giving**ONE",
    "please?",
    "revert",
    "with",
    '"\\!--Two',
    "]{",
    "Sure",
    "here",
    "$\\",
    "tutorial",
    "!!",
    "manuallyfor",
    "Wikipedia",
    "}",
    "%{",
    "cheers",
    "Ir",
    "voil",
    "->",
    "'''",
    "==>",
    "</s>",
    "[/",
    "INST]",
    "Title:",
    "Lets",
    "chaotically",
    "zanimation",
    "<<",
    "@@",
    "ln",
    "mode",
    "AA",
    "explode",
    "prefix",
]


def gcg_like(rng: random.Random, n_tokens: int = 24) -> str:
    return " ".join(rng.choice(_GCG_ALPHABET) for _ in range(n_tokens))


def roc_auc(pos: list[float], neg: list[float]) -> float:
    """AUC via the Mann-Whitney U statistic: P(score_pos > score_neg)."""
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(pos) * len(neg))


def best_threshold(pos: list[float], neg: list[float]) -> dict[str, float]:
    """The threshold that maximises TPR - FPR, with its FPR/FNR."""
    best = {"threshold": float("nan"), "tpr": 0.0, "fpr": 1.0, "fnr": 1.0, "youden": -1.0}
    for t in sorted(set(pos + neg)):
        tpr = sum(1 for p in pos if p >= t) / len(pos)
        fpr = sum(1 for n in neg if n >= t) / len(neg)
        if tpr - fpr > best["youden"]:
            best = {"threshold": t, "tpr": tpr, "fpr": fpr, "fnr": 1 - tpr, "youden": tpr - fpr}
    return best


def main() -> int:
    rng = random.Random(20260902)
    started = time.time()
    scorer = PerplexityScorer()
    scorer.load()

    benign = [c["text"] for c in json.loads((FIX / "benign" / "corpus.json").read_text())["cases"]]
    natural = [
        c["text"] for c in json.loads((FIX / "injections" / "corpus.json").read_text())["cases"]
    ]
    gcg = [gcg_like(rng) for _ in range(len(natural))]
    repeated = [f"{t} {t}" for t in natural]
    embedded = [
        f"{b} {t}" for b, t in zip(benign, natural, strict=False)
    ]  # injection appended to benign prose

    def score_all(texts: list[str]) -> list[float]:
        return [scorer.score(t).mean for t in texts]

    print("scoring ...", flush=True)
    s_benign, s_natural, s_gcg, s_repeated, s_embedded = map(
        score_all, (benign, natural, gcg, repeated, embedded)
    )

    def summary(xs: list[float]) -> dict[str, float]:
        return {
            "mean": round(statistics.mean(xs), 2),
            "median": round(statistics.median(xs), 2),
            "min": round(min(xs), 2),
            "max": round(max(xs), 2),
            "n": len(xs),
        }

    results: dict[str, Any] = {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "commit": subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=REPO, capture_output=True, text=True
        ).stdout.strip(),
        "command": "uv run python bench/perplexity_experiment.py",
        "scorer": {
            "model": scorer.model_name,
            "window": scorer.window,
            "stride": scorer.stride,
            "statistic": "mean per-token perplexity",
        },
        "corpora": {
            "benign": summary(s_benign),
            "natural_injections": summary(s_natural),
            "gcg_like": summary(s_gcg),
            "natural_repeated_once": summary(s_repeated),
            "natural_embedded_in_benign": summary(s_embedded),
        },
        "a_gcg_vs_benign": {
            "auc": round(roc_auc(s_gcg, s_benign), 4),
            **best_threshold(s_gcg, s_benign),
        },
        "b_natural_vs_benign": {
            "auc": round(roc_auc(s_natural, s_benign), 4),
            **best_threshold(s_natural, s_benign),
        },
        "b2_embedded_vs_benign": {
            "auc": round(roc_auc(s_embedded, s_benign), 4),
            **best_threshold(s_embedded, s_benign),
        },
        "c_repetition_attack": {
            "auc_repeated_vs_benign": round(roc_auc(s_repeated, s_benign), 4),
            "mean_before": round(statistics.mean(s_natural), 2),
            "mean_after_one_duplication": round(statistics.mean(s_repeated), 2),
            "benign_mean": round(statistics.mean(s_benign), 2),
            "fraction_of_injections_below_benign_mean_after_duplication": round(
                sum(1 for x in s_repeated if x < statistics.mean(s_benign)) / len(s_repeated), 3
            ),
            "fraction_of_injections_below_benign_mean_before": round(
                sum(1 for x in s_natural if x < statistics.mean(s_benign)) / len(s_natural), 3
            ),
        },
        "raw": {
            "benign": [round(x, 2) for x in s_benign],
            "natural": [round(x, 2) for x in s_natural],
            "gcg": [round(x, 2) for x in s_gcg],
            "repeated": [round(x, 2) for x in s_repeated],
            "embedded": [round(x, 2) for x in s_embedded],
        },
        "duration_s": round(time.time() - started, 1),
    }

    # Write the numbers *before* plotting, so a plotting failure can never lose them.
    OUT_JSON_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_JSON_DIR / f"perplexity_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(started))}.json"
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    # -- plots -------------------------------------------------------------------
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    PLOTS.mkdir(parents=True, exist_ok=True)

    def roc_points(pos: list[float], neg: list[float]) -> tuple[list[float], list[float]]:
        ts = sorted(set(pos + neg), reverse=True)
        xs = [0.0]
        ys = [0.0]
        for t in ts:
            xs.append(sum(1 for n in neg if n >= t) / len(neg))
            ys.append(sum(1 for p in pos if p >= t) / len(pos))
        return xs, ys

    fig, ax = plt.subplots(figsize=(5.5, 5))
    curves = (
        ("(a) GCG-style vs benign", s_gcg, results["a_gcg_vs_benign"]["auc"]),
        ("(b) natural-language vs benign", s_natural, results["b_natural_vs_benign"]["auc"]),
        (
            "(c) natural, duplicated once, vs benign",
            s_repeated,
            results["c_repetition_attack"]["auc_repeated_vs_benign"],
        ),
    )
    for label, pos, auc in curves:
        xs, ys = roc_points(pos, s_benign)
        ax.plot(xs, ys, label=f"{label}  AUC={auc:.2f}")
    ax.plot([0, 1], [0, 1], "k--", lw=0.8, label="chance")
    ax.set_xlabel("false positive rate (benign flagged)")
    ax.set_ylabel("true positive rate (injection flagged)")
    ax.set_title("GPT-2 perplexity as an injection detector")
    ax.legend(fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(PLOTS / "perplexity_roc.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.boxplot(
        [s_benign, s_gcg, s_natural, s_embedded, s_repeated],
        tick_labels=[
            "benign",
            "GCG-style",
            "natural\ninjection",
            "injection in\nbenign prose",
            "injection\nduplicated x1",
        ],
        showfliers=True,
    )
    ax.set_yscale("log")
    ax.set_ylabel("mean per-token perplexity (log)")
    benign_mean = statistics.mean(s_benign)
    ax.axhline(benign_mean, color="grey", ls=":", lw=1, label=f"benign mean {benign_mean:.1f}")
    ax.set_title("Perplexity by corpus")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(PLOTS / "perplexity_distributions.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.scatter(s_natural, s_repeated, s=18)
    lim = max(max(s_natural), max(s_repeated)) * 1.05
    ax.plot([0, lim], [0, lim], "k--", lw=0.8, label="no change")
    ax.axhline(benign_mean, color="grey", ls=":", lw=1, label=f"benign mean {benign_mean:.1f}")
    ax.set_xlabel("perplexity, injection as written")
    ax.set_ylabel("perplexity, injection duplicated once")
    ax.set_title("The repetition attack")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(PLOTS / "perplexity_repetition.png", dpi=150)
    plt.close(fig)

    results["plots"] = [
        "docs/plots/perplexity_roc.png",
        "docs/plots/perplexity_distributions.png",
        "docs/plots/perplexity_repetition.png",
    ]
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    for k in (
        "corpora",
        "a_gcg_vs_benign",
        "b_natural_vs_benign",
        "b2_embedded_vs_benign",
        "c_repetition_attack",
    ):
        print(k, json.dumps(results[k], indent=1))
    print(f"\nwrote {out.relative_to(REPO)} and {len(results['plots'])} plots")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Offline, label-driven evaluation of candidate secret-detection plugins.

Given a fixed synthetic, fully labelled corpus, this package quantifies which
plugins are worth enabling for our codebase. Every metric is computed per
source-file family, so a plugin whose global numbers improve while regressing
on one family cannot hide behind the aggregate. No network access and no
verification is involved; only synthetic labels are consumed.
"""
from .dataset import LabeledDataset
from .dataset import LabeledFile
from .dataset import load_dataset
from .dataset import TruthLabel
from .engine import available_plugin_names
from .engine import run_all
from .engine import run_plugin
from .matching import Hit
from .matching import match_dataset
from .matching import MatchResult
from .metrics import compare_configurations
from .metrics import ConfigurationComparison
from .metrics import evaluate
from .metrics import evaluate_dataset
from .metrics import EvaluationReport
from .metrics import FamilySummary
from .metrics import PluginFamilyMetrics
from .metrics import PluginFailure
from .report import render_json_report
from .report import render_text_report

__all__ = (
    "LabeledDataset",
    "LabeledFile",
    "TruthLabel",
    "load_dataset",
    "Hit",
    "MatchResult",
    "match_dataset",
    "run_all",
    "run_plugin",
    "available_plugin_names",
    "evaluate",
    "evaluate_dataset",
    "EvaluationReport",
    "PluginFamilyMetrics",
    "FamilySummary",
    "PluginFailure",
    "ConfigurationComparison",
    "compare_configurations",
    "render_text_report",
    "render_json_report",
)

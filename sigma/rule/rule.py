from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from typing import Self

import sigma.exceptions as sigma_exceptions
from sigma.exceptions import SigmaError, SigmaRuleLocation
from sigma.processing.tracking import ProcessingItemTrackingMixin
from sigma.rule.base import SigmaRuleBase
from sigma.rule.detection import EmptySigmaDetections, SigmaDetections
from sigma.rule.logsource import EmptyLogSource, SigmaLogSource

if TYPE_CHECKING:
    from sigma.filters import SigmaFilterApplication
    from sigma.policy import SigmaPolicy


@dataclass
class SigmaRule(SigmaRuleBase, ProcessingItemTrackingMixin):
    """
    A single Sigma rule.
    """

    logsource: SigmaLogSource = field(default_factory=SigmaLogSource)
    detection: SigmaDetections = field(default_factory=EmptySigmaDetections)
    # Provenance records for filters applied to this rule. They are intentionally excluded
    # from equality/serialization and retain the exact rule and filter objects.
    applied_filters: list["SigmaFilterApplication"] = field(
        default_factory=list, compare=False, repr=False
    )

    @property
    def filter_applications(self: Self) -> list["SigmaFilterApplication"]:
        """Alias for :attr:`applied_filters`."""
        return self.applied_filters

    def filter_report(self: Self) -> dict[str, Any]:
        """
        Return an inspectable report of the filters applied to this rule.

        The report pairs the rule's final conditions and conversion result with one entry per
        applied filter, including the filter's source location. It can therefore be used
        after conversion to determine which rule still alerts and which material contributed
        each exception.
        """
        return {
            "rule": {
                "title": self.title,
                "id": str(self.id) if self.id is not None else None,
                "name": self.name,
                "source": str(self.source) if self.source is not None else None,
            },
            "conditions": list(self.detection.condition),
            "applications": [application.to_dict() for application in self.applied_filters],
            "filters": [application.to_dict() for application in self.applied_filters],
            "conversion_result": self._conversion_result,
            "alerts": self._output and bool(self.detection.condition),
            "alerting": self._output and bool(self.detection.condition),
        }

    def get_filter_provenance(self: Self) -> dict[str, Any]:
        """Alias for :meth:`filter_report`."""
        return self.filter_report()

    def get_filter_report(self: Self) -> dict[str, Any]:
        """Alias for :meth:`filter_report`."""
        return self.filter_report()

    def filter_application_by_namespace(
        self: Self, namespace: str
    ) -> "SigmaFilterApplication | None":
        """Return the filter application owning *namespace*, if any."""
        return next(
            (
                application
                for application in self.applied_filters
                if application.namespace == namespace
            ),
            None,
        )

    def filter_application_for_detection(
        self: Self, detection_name: str
    ) -> "SigmaFilterApplication | None":
        """Return the filter application that owns a detection (original or qualified name)."""
        for application in self.applied_filters:
            if detection_name in application.detections or detection_name in (
                application.detections.values()
            ):
                return application
        return None

    @classmethod
    def from_dict(  # type: ignore[override]
        cls: type[Self],
        rule: dict[str, Any],
        collect_errors: bool = False,
        source: SigmaRuleLocation | None = None,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        """
        Convert Sigma rule parsed in dict structure into SigmaRule object.

        if collect_errors is set to False exceptions are collected in the errors property of the resulting
        SigmaRule object. Else the first recognized error is raised as exception.
        """
        kwargs, errors = super().from_dict_common_params(
            rule, collect_errors, source, policy=policy
        )

        # parse log source
        try:
            logsource = SigmaLogSource.from_dict(rule["logsource"], source)
        except KeyError:
            logsource = EmptyLogSource()
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma rule must have a log source", source=source
                )
            )
        except AttributeError:
            logsource = EmptyLogSource()
            errors.append(
                sigma_exceptions.SigmaLogsourceError(
                    "Sigma logsource must be a valid YAML map", source=source
                )
            )
        except SigmaError as e:
            logsource = EmptyLogSource()
            errors.append(e)

        # parse detections
        try:
            detections = SigmaDetections.from_dict(rule["detection"], source, policy=policy)
        except KeyError:
            detections = EmptySigmaDetections()
            errors.append(
                sigma_exceptions.SigmaDetectionError(
                    "Sigma rule must have a detection definitions", source=source
                )
            )
        except TypeError:
            detections = EmptySigmaDetections()
            errors.append(
                sigma_exceptions.SigmaDetectionError(
                    "Sigma detection must be a valid YAML map", source=source
                )
            )
        except SigmaError as e:
            detections = EmptySigmaDetections()
            errors.append(e)

        if not collect_errors and errors:
            raise errors[0]

        return cls(
            logsource=logsource,
            detection=detections,
            errors=errors,
            **kwargs,
        )

    @classmethod
    def from_yaml(
        cls: type[Self],
        rule: str,
        collect_errors: bool = False,
        policy: "SigmaPolicy | None" = None,
    ) -> Self:
        """Convert YAML input string with single document into SigmaRule object."""
        return super().from_yaml(rule, collect_errors, policy=policy)

    def to_dict(self) -> dict[str, Any]:
        """Convert rule object into dict."""
        d = super().to_dict()
        d.update(
            {
                "logsource": self.logsource.to_dict(),
                "detection": self.detection.to_dict(),
            }
        )

        return d

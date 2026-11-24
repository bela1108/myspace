"""XML parser security profiles and capability descriptions."""

CAPABILITY_DTD = "forbid_dtd"
CAPABILITY_ENTITIES = "forbid_entities"
CAPABILITY_EXTERNAL = "forbid_external"
CAPABILITY_DEPTH = "max_element_depth"
CAPABILITY_ENTITY_EXPANSIONS = "max_entity_expansions"

CAPABILITIES = (
    CAPABILITY_DTD,
    CAPABILITY_ENTITIES,
    CAPABILITY_EXTERNAL,
    CAPABILITY_DEPTH,
    CAPABILITY_ENTITY_EXPANSIONS,
)

POLICY_FIELDS = CAPABILITIES

STATUS_GREEN = "green"
STATUS_RED = "red"
STATUS_NOT_REQUESTED = "not_requested"


class CapabilityError(ValueError):
    """A requested security capability is not available."""

    def __init__(self, backend, missing_capabilities):
        self.backend = backend
        self.missing_capabilities = tuple(missing_capabilities)
        reasons = "; ".join(
            "{}: {}".format(item["capability"], item["reason"])
            for item in self.missing_capabilities
        )
        super().__init__("{} cannot satisfy policy: {}".format(backend, reasons))


class PolicyProfile(object):
    """Security settings requested from an XML parser adapter."""

    def __init__(
        self,
        name,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
        max_element_depth=None,
        max_entity_expansions=None,
        description="",
    ):
        self.name = name
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        self.max_element_depth = max_element_depth
        self.max_entity_expansions = max_entity_expansions
        self.description = description

    @property
    def settings(self):
        return {
            CAPABILITY_DTD: self.forbid_dtd,
            CAPABILITY_ENTITIES: self.forbid_entities,
            CAPABILITY_EXTERNAL: self.forbid_external,
            CAPABILITY_DEPTH: self.max_element_depth,
            CAPABILITY_ENTITY_EXPANSIONS: self.max_entity_expansions,
        }

    def as_dict(self):
        result = self.settings
        result["name"] = self.name
        result["description"] = self.description
        return result


STRICT_POLICY = PolicyProfile(
    name="strict",
    forbid_dtd=True,
    forbid_entities=True,
    forbid_external=True,
    max_element_depth=100,
    max_entity_expansions=0,
    description="Deny DTDs, entities, external references, and excessive nesting.",
)

BALANCED_POLICY = PolicyProfile(
    name="balanced",
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    max_element_depth=250,
    max_entity_expansions=None,
    description="Allow safe documents without DTD entity declarations.",
)

COMPATIBILITY_POLICY = PolicyProfile(
    name="compatibility",
    forbid_dtd=False,
    forbid_entities=False,
    forbid_external=True,
    max_element_depth=None,
    max_entity_expansions=None,
    description="Preserve DTD and entity behavior while blocking external access.",
)

POLICY_PROFILES = {
    STRICT_POLICY.name: STRICT_POLICY,
    BALANCED_POLICY.name: BALANCED_POLICY,
    COMPATIBILITY_POLICY.name: COMPATIBILITY_POLICY,
}


def get_policy_profile(name):
    try:
        return POLICY_PROFILES[name]
    except KeyError:
        raise KeyError(
            "unknown policy profile {!r}; available profiles: {}".format(
                name, ", ".join(sorted(POLICY_PROFILES))
            )
        )


def capability(capability_name, supported, requested, default, default_source, reason=None):
    if requested is None:
        status = STATUS_NOT_REQUESTED
    elif supported:
        status = STATUS_GREEN
    else:
        status = STATUS_RED
    if reason is None:
        if status == STATUS_GREEN:
            reason = "capability is enforced by adapter"
        elif status == STATUS_NOT_REQUESTED:
            reason = "policy does not request this capability"
    return {
        "capability": capability_name,
        "status": status,
        "supported": supported,
        "requested": requested,
        "default": default,
        "default_source": default_source,
        "reason": reason,
    }


def missing_capabilities(capability_matrix):
    return [
        entry
        for entry in capability_matrix
        if entry["status"] == STATUS_RED
    ]


__all__ = [
    "BALANCED_POLICY",
    "CAPABILITIES",
    "CAPABILITY_DEPTH",
    "CAPABILITY_DTD",
    "CAPABILITY_ENTITIES",
    "CAPABILITY_ENTITY_EXPANSIONS",
    "CAPABILITY_EXTERNAL",
    "CapabilityError",
    "COMPATIBILITY_POLICY",
    "POLICY_PROFILES",
    "PolicyProfile",
    "STRICT_POLICY",
    "capability",
    "get_policy_profile",
    "missing_capabilities",
]

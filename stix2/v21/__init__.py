"""STIX 2.1 API Objects.

.. autosummary::
   :toctree: v21

   bundle
   common
   observables
   sdo
   sro

|
"""

# flake8: noqa

from .base import (
    _DomainObject, _Extension, _Observable, _RelationshipObject, _STIXBase21,
)
from .bundle import Bundle
from .common import (
    TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, CustomExtension, CustomMarking,
    ExtensionDefinition, ExternalReference, GranularMarking, KillChainPhase,
    LanguageContent, MarkingDefinition, StatementMarking, TLPMarking,
)
from .observables import (
    URL, AlternateDataStream, ArchiveExt, Artifact, AutonomousSystem,
    CustomObservable, Directory, DomainName, EmailAddress, EmailMessage,
    EmailMIMEComponent, File, HTTPRequestExt, ICMPExt, IPv4Address,
    IPv6Address, MACAddress, Mutex, NetworkTraffic, NTFSExt, PDFExt, Process,
    RasterImageExt, SocketExt, Software, TCPExt, UNIXAccountExt, UserAccount,
    WindowsPEBinaryExt, WindowsPEOptionalHeaderType, WindowsPESection,
    WindowsProcessExt, WindowsRegistryKey, WindowsRegistryValueType,
    WindowsServiceExt, X509Certificate, X509V3ExtensionsType,
)
from .sdo import (
    AttackPattern, Campaign, CourseOfAction, CustomObject, Grouping, Identity,
    Incident, Indicator, Infrastructure, IntrusionSet, Location, Malware,
    MalwareAnalysis, Note, ObservedData, Opinion, Report, ThreatActor, Tool,
    Vulnerability,
)
from .sro import Relationship, Sighting

OBJ_MAP = {
    'attack-pattern': AttackPattern,
    'bundle': Bundle,
    'campaign': Campaign,
    'course-of-action': CourseOfAction,
    'grouping': Grouping,
    'identity': Identity,
    'incident': Incident,
    'indicator': Indicator,
    'infrastructure': Infrastructure,
    'intrusion-set': IntrusionSet,
    'language-content': LanguageContent,
    'location': Location,
    'malware': Malware,
    'malware-analysis': MalwareAnalysis,
    'note': Note,
    'marking-definition': MarkingDefinition,
    'observed-data': ObservedData,
    'opinion': Opinion,
    'report': Report,
    'relationship': Relationship,
    'threat-actor': ThreatActor,
    'tool': Tool,
    'sighting': Sighting,
    'extension-definition': ExtensionDefinition,
    'vulnerability': Vulnerability,
}

OBJ_MAP_OBSERVABLE = {
    'artifact': Artifact,
    'autonomous-system': AutonomousSystem,
    'directory': Directory,
    'domain-name': DomainName,
    'email-addr': EmailAddress,
    'email-message': EmailMessage,
    'file': File,
    'ipv4-addr': IPv4Address,
    'ipv6-addr': IPv6Address,
    'mac-addr': MACAddress,
    'mutex': Mutex,
    'network-traffic': NetworkTraffic,
    'process': Process,
    'software': Software,
    'url': URL,
    'user-account': UserAccount,
    'windows-registry-key': WindowsRegistryKey,
    'x509-certificate': X509Certificate,
}

EXT_MAP = {
    'archive-ext': ArchiveExt,
    'ntfs-ext': NTFSExt,
    'pdf-ext': PDFExt,
    'raster-image-ext': RasterImageExt,
    'windows-pebinary-ext': WindowsPEBinaryExt,
    'http-request-ext': HTTPRequestExt,
    'icmp-ext': ICMPExt,
    'socket-ext': SocketExt,
    'tcp-ext': TCPExt,
    'windows-process-ext': WindowsProcessExt,
    'windows-service-ext': WindowsServiceExt,
    'unix-account-ext': UNIXAccountExt,
}

# Ensure star-imports from this module get the right symbols.  "base" is a
# known problem, since there are multiple modules with that name and one can
# accidentally overwrite another.
__all__ = """
    Bundle,

    TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, CustomMarking, ExtensionDefinition,
    ExternalReference, GranularMarking, KillChainPhase, LanguageContent,
    MarkingDefinition, StatementMarking, TLPMarking,

    URL, AlternateDataStream, ArchiveExt, Artifact, AutonomousSystem,
    CustomExtension, CustomObservable, Directory, DomainName, EmailAddress,
    EmailMessage, EmailMIMEComponent, File, HTTPRequestExt, ICMPExt,
    IPv4Address, IPv6Address, MACAddress, Mutex, NetworkTraffic, NTFSExt,
    PDFExt, Process, RasterImageExt, SocketExt, Software, TCPExt,
    UNIXAccountExt, UserAccount, WindowsPEBinaryExt,
    WindowsPEOptionalHeaderType, WindowsPESection, WindowsProcessExt,
    WindowsRegistryKey, WindowsRegistryValueType, WindowsServiceExt,
    X509Certificate, X509V3ExtensionsType,

    AttackPattern, Campaign, CourseOfAction, CustomObject, Grouping, Identity,
    Incident, Indicator, Infrastructure, IntrusionSet, Location, Malware,
    MalwareAnalysis, Note, ObservedData, Opinion, Report, ThreatActor, Tool,
    Vulnerability,

    Relationship, Sighting,

    OBJ_MAP, OBJ_MAP_OBSERVABLE, EXT_MAP
""".replace(",", " ").split()

from ..migration import (  # noqa: E402
    ConversionResult, Converter, Diagnostic, IDMap, ObjectCollection,
    ObservedDataConversion, ObservedDataConversionError,
    ObservedDataConverter, ObservedDataIDMap, ObservedDataImporter,
    UnresolvedContent, UnresolvedReference,
    convert_observed_data, convert_observed_data_2_0_to_2_1,
    convert_observed_data_to_2_1, convert_observed_data_v20_to_21,
    convert_observed_data_v20_to_v21,
    convert_observed_data_to_21, convert_observed_data_to_v21,
    extract_observed_data_objects, extract_observed_objects,
    import_observed_data, migrate_observed_data,
    migrate_observed_data_to_v21, observed_data_to_21,
    observed_data_to_objects,
    observed_data_to_v21, upgrade_observed_data,
)

__all__ += [
    "ConversionResult", "Diagnostic", "IDMap", "ObjectCollection",
    "ObservedDataConversion", "ObservedDataConversionError",
    "ObservedDataConverter", "ObservedDataIDMap",
    "UnresolvedContent", "UnresolvedReference",
    "convert_observed_data", "convert_observed_data_2_0_to_2_1",
    "convert_observed_data_to_2_1", "convert_observed_data_to_21",
    "convert_observed_data_to_v21", "convert_observed_data_v20_to_21",
    "convert_observed_data_v20_to_v21",
    "import_observed_data", "migrate_observed_data",
    "migrate_observed_data_to_v21", "observed_data_to_21",
    "observed_data_to_v21", "upgrade_observed_data",
]

from .. import migration  # noqa: E402,F401
from ..migration import __all__ as _migration_all  # noqa: E402

__all__ += [name for name in _migration_all if name not in __all__]

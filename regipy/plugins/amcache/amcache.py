import logging

from inflection import underscore

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import AMCACHE_HIVE_TYPE
from regipy.plugins.amcache.evidence import verify_amcache_evidence
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

AMCACHE_FIELD_NUMERIC_MAPPINGS = {
    "0": "product_name",
    "1": "company_name",
    "2": "file_version_number",
    "3": "language_code",
    "4": "switchback_context",
    "5": "file_version",
    "6": "file_size",
    "7": "pe_header_hash",
    "8": "unknown1",
    "9": "pe_header_checksum",
    "a": "unknown2",
    "b": "unknown3",
    "c": "file_description",
    "d": "unknown4",
    "f": "linker_compile_time",
    "10": "unknown5",
    "11": "last_modified_timestamp",
    "12": "created_timestamp",
    "15": "full_path",
    "16": "unknown6",
    "17": "last_modified_timestamp_2",
    "100": "program_id",
    "101": "sha1",
}

WIN8_TS_FIELDS = [
    "last_modified_timestamp",
    "created_timestamp",
    "last_modified_timestamp_2",
]

ROOT_FILE_GENERATION = "root_file"
INVENTORY_APPLICATION_FILE_GENERATION = "inventory_application_file"


class AmCachePlugin(Plugin):
    NAME = "amcache"
    DESCRIPTION = "Parse Amcache"
    COMPATIBLE_HIVE = AMCACHE_HIVE_TYPE

    def __init__(self, registry_hive, as_json=False, trim_values=False, include_evidence_source=False):
        super().__init__(registry_hive, as_json=as_json, trim_values=trim_values)
        self.include_evidence_source = include_evidence_source

    def _build_evidence_source(self, subkey, registry_key_path, windows_generation):
        numeric_value_sources = []
        hash_sources = []

        for value in subkey.iter_values(as_json=self.as_json):
            if value.name in AMCACHE_FIELD_NUMERIC_MAPPINGS:
                numeric_value_sources.append(
                    {
                        "registry_value_name": value.name,
                        "output_field": AMCACHE_FIELD_NUMERIC_MAPPINGS[value.name],
                        "raw_value": value.value,
                    }
                )

            if value.name.lower() == "fileid":
                hash_sources.append(
                    {
                        "source_format": "file_id",
                        "registry_value_name": value.name,
                        "output_field": "file_id",
                        "raw_value": value.value,
                    }
                )

        for source in numeric_value_sources:
            if source["registry_value_name"] == "101":
                hash_sources.append(
                    {
                        "source_format": "numeric",
                        "registry_value_name": "101",
                        "output_field": "sha1",
                        "raw_value": source["raw_value"],
                    }
                )

        return {
            "registry_key_path": registry_key_path,
            "windows_generations": [windows_generation],
            "numeric_value_sources": numeric_value_sources,
            "hash_sources": hash_sources,
        }

    def parse_amcache_file_entry(self, subkey, registry_key_path=None, windows_generation=None):
        entry = {underscore(x.name): x.value for x in subkey.iter_values(as_json=self.as_json)}
        evidence_source = None
        if self.include_evidence_source:
            evidence_source = self._build_evidence_source(subkey, registry_key_path, windows_generation)

        # Sometimes the value names might be numeric instead. Translate them:
        for k, v in AMCACHE_FIELD_NUMERIC_MAPPINGS.items():
            content = entry.pop(k, None)
            if content:
                entry[v] = content

        if "sha1" in entry:
            entry["sha1"] = entry["sha1"][4:]
            if evidence_source:
                for source in evidence_source["hash_sources"]:
                    if source["output_field"] == "sha1":
                        source["normalized_value"] = entry["sha1"]

        if "file_id" in entry and entry["file_id"] != 0:
            raw_file_id = entry["file_id"]
            entry["file_id"] = entry["file_id"][4:]
            if evidence_source:
                for source in evidence_source["hash_sources"]:
                    if source["output_field"] == "file_id":
                        source["normalized_value"] = entry["file_id"]
                        source["strip_prefix_chars"] = 4
                        source["raw_value_before_normalization"] = raw_file_id
            if "sha1" not in entry:
                entry["sha1"] = entry["file_id"]
                if evidence_source:
                    for source in evidence_source["hash_sources"]:
                        if source["output_field"] == "file_id":
                            evidence_source["hash_sources"].append(
                                {
                                    **source,
                                    "output_field": "sha1",
                                    "copied_from_file_id": True,
                                }
                            )

        if "program_id" in entry:
            entry["program_id"] = entry["program_id"][4:]

        entry["timestamp"] = convert_wintime(subkey.header.last_modified, as_json=self.as_json)

        if "size" in entry:
            entry["size"] = int(entry["size"], 16) if isinstance(entry["size"], str) else entry["size"]

        is_pefile = entry.get("is_pe_file")
        if is_pefile is not None:
            entry["is_pe_file"] = bool(is_pefile)

        is_os_component = entry.get("is_os_component")
        if is_os_component is not None:
            entry["is_os_component"] = bool(is_os_component)

        if entry.get("link_date") == 0:
            entry.pop("link_date")

        for ts_field_name in WIN8_TS_FIELDS:
            ts = entry.pop(ts_field_name, None)
            if ts:
                entry[ts_field_name] = convert_wintime(ts, as_json=self.as_json)

        if evidence_source:
            entry["amcache_source"] = evidence_source

        self.entries.append(entry)  # type: ignore[union-attr]

    def verify_evidence(
        self,
        evidence_files,
        hash_rules,
        entry_evidence_ids=None,
        rule_resolver=None,
    ):
        return verify_amcache_evidence(
            entries=self.entries,  # type: ignore[arg-type]
            evidence_files=evidence_files,
            hash_rules=hash_rules,
            entry_evidence_ids=entry_evidence_ids,
            rule_resolver=rule_resolver,
        )

    def run(self):
        logger.debug("Started AmCache Plugin...")

        try:
            amcache_file_subkey = self.registry_hive.get_key(r"\Root\File")
        except RegistryKeyNotFoundException:
            logger.error(r"Could not find \Root\File subkey")
            amcache_file_subkey = None

        try:
            amcache_inventory_file_subkey = self.registry_hive.get_key(r"\Root\InventoryApplicationFile")
        except RegistryKeyNotFoundException:
            logger.info(r"Could not find \Root\InventoryApplicationFile subkey")
            amcache_inventory_file_subkey = None

        if amcache_file_subkey:
            for subkey in amcache_file_subkey.iter_subkeys():
                if subkey.header.subkey_count > 0 and subkey.iter_subkeys() is not None:
                    for file_subkey in subkey.iter_subkeys():
                        registry_key_path = rf"\Root\{amcache_file_subkey.name}\{subkey.name}\{file_subkey.name}"
                        self.parse_amcache_file_entry(
                            file_subkey,
                            registry_key_path=registry_key_path,
                            windows_generation=ROOT_FILE_GENERATION,
                        )
                if subkey.header.values_count > 0:
                    self.entries.append(subkey)  # type: ignore[union-attr]

        if amcache_inventory_file_subkey:
            for file_subkey in amcache_inventory_file_subkey.iter_subkeys():
                registry_key_path = rf"\Root\{amcache_inventory_file_subkey.name}\{file_subkey.name}"
                self.parse_amcache_file_entry(
                    file_subkey,
                    registry_key_path=registry_key_path,
                    windows_generation=INVENTORY_APPLICATION_FILE_GENERATION,
                )

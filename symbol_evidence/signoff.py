"""Parsers for symbol-library sign-off sheets and source-location claims."""

import csv
import io
import json
import os
import re

from .model import (
    Claim,
    SignoffEntry,
    _clean_text,
    normalise_age,
    normalise_guid,
    parse_digest,
    parse_identity_value,
)


def _header_key(value):
    text = _clean_text(value).lower()
    text = text.replace("\ufeff", "")
    text = re.sub(r"[\s_\-./\\()（）\[\]{}:：]+", "", text)
    return text


_ALIASES = {
    "name": {
        "name",
        "displayname",
        "library",
        "libraryname",
        "pdb",
        "pdbname",
        "pdbpath",
        "pdb文件",
        "file",
        "filename",
        "filepath",
        "文件名",
        "文件路径",
        "符号库",
        "符号库名称",
        "库名",
        "名称",
        "显示名",
    },
    "guid": {
        "guid",
        "pdbguid",
        "signatureguid",
        "cvguid",
        "调试标识",
        "调试guid",
        "pdb标识",
        "pdbguidage",
    },
    "age": {"age", "pdbage", "cvage", "年龄", "版本", "符号版本"},
    "signature": {
        "signature",
        "identity",
        "pdbidentity",
        "pdb签名",
        "签名",
        "调试签名",
        "guidage",
        "guid+age",
        "pdbguid+age",
    },
    "digest": {
        "digest",
        "digestvalue",
        "hash",
        "hashvalue",
        "filehash",
        "filesha256",
        "artifactsha256",
        "symbolfilesha256",
        "checksum",
        "pdbhash",
        "pdbsha",
        "pdbsha1",
        "pdbsha256",
        "pdbsha512",
        "sha",
        "sha1",
        "sha256",
        "sha512",
        "摘要",
        "文件摘要",
        "文件sha256",
        "sha256摘要",
        "摘要sha256",
        "符号库摘要",
        "pdb摘要",
        "校验值",
    },
    "pe_digest": {
        "pehash",
        "pefilehash",
        "pesha",
        "pesha1",
        "pesha256",
        "pesha512",
        "imagesha256",
        "imagesha512",
        "binarysha256",
        "binarysha512",
        "releaseimagesha256",
        "releaseimagesha512",
        "镜像摘要",
        "镜像校验值",
        "pe摘要",
        "发行镜像摘要",
    },
    "signer": {
        "signer",
        "signedby",
        "approvedby",
        "reviewer",
        "owner",
        "签收人",
        "审核人",
        "批准人",
        "经办人",
        "签名人",
    },
    "signed_at": {
        "signedat",
        "signeddate",
        "date",
        "timestamp",
        "time",
        "签收日期",
        "签收时间",
        "日期",
        "时间",
    },
    "reference": {
        "reference",
        "ref",
        "receipt",
        "receiptid",
        "ticket",
        "ticketid",
        "单号",
        "签收单号",
        "登记号",
        "凭据",
        "依据",
    },
    "notes": {"notes", "note", "comment", "comments", "remark", "备注", "说明"},
}


_PREFERRED = {
    "name": (
        "displayname",
        "name",
        "libraryname",
        "library",
        "pdbname",
        "pdbpath",
        "pdb",
        "filename",
        "filepath",
        "file",
        "符号库名称",
        "符号库",
        "名称",
        "显示名",
        "文件名",
        "文件路径",
    ),
    "digest": (
        "digest",
        "pdbsha256",
        "sha256",
        "pdbhash",
        "pdbsha",
        "hash",
        "sha",
        "sha1",
        "sha512",
        "pdbsha1",
        "pdbsha512",
        "文件摘要",
        "符号库摘要",
        "pdb摘要",
        "摘要",
        "校验值",
    ),
    "pe_digest": (
        "pesha256",
        "pesha512",
        "pehash",
        "pesha",
        "imagesha256",
        "imagesha512",
        "binarysha256",
        "binarysha512",
        "镜像摘要",
        "镜像校验值",
        "pe摘要",
        "发行镜像摘要",
    ),
}


def _lookup(row, field):
    aliases = _ALIASES[field]
    normalised = {_header_key(key): value for key, value in row.items()}
    for alias in _PREFERRED.get(field, ()):
        key = _header_key(alias)
        if key in normalised and _clean_text(normalised[key]):
            return normalised[key]
    for alias in aliases:
        key = _header_key(alias)
        if key in normalised and _clean_text(normalised[key]):
            return normalised[key]
    return None


def _decode_identity(guid, age, signature):
    guid = normalise_guid(guid)
    age = normalise_age(age)
    sig_kind, sig_value, sig_age = parse_identity_value(signature)
    if guid is None and sig_kind == "rsds":
        guid = sig_value
    if age is None and sig_kind in ("rsds", "nb10"):
        age = sig_age
    if guid is not None and age is not None:
        return guid, age, None
    if sig_kind == "nb10" and sig_value:
        return None, age, sig_value
    return guid, age, _clean_text(signature).upper() or None


def _looks_like_pe(name):
    suffix = os.path.splitext(_clean_text(name).replace("\\", "/"))[1].lower()
    return suffix in (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx")


def _entry_from_row(row, index):
    name = _clean_text(_lookup(row, "name"))
    pdb_path = ""
    if name.lower().endswith(".pdb") and ("\\" in name or "/" in name):
        pdb_path = name
    if not pdb_path:
        for key, value in row.items():
            if _header_key(key) in (
                "pdbpath",
                "pdb文件路径",
                "pdb",
                "pdb文件",
                "符号库路径",
                "filepath",
                "文件路径",
            ):
                pdb_path = _clean_text(value)
                break

    root_name = _clean_text(os.path.basename(pdb_path.replace("\\", "/")))
    if root_name.lower().endswith(".pdb") and not name:
        name = root_name

    guid, age, signature = _decode_identity(
        _lookup(row, "guid"),
        _lookup(row, "age"),
        _lookup(row, "signature"),
    )
    digest = _lookup(row, "digest")
    pe_digest = _lookup(row, "pe_digest")
    if (
        digest is not None
        and pe_digest is None
        and _looks_like_pe(name or pdb_path)
        and not guid
        and not age
    ):
        pe_digest = digest
        digest = None
    return SignoffEntry(
        name=name,
        pdb_path=pdb_path,
        guid=guid,
        age=age,
        signature=signature,
        digest=parse_digest(digest) if digest is not None else None,
        pe_digest=parse_digest(pe_digest) if pe_digest is not None else None,
        signer=_lookup(row, "signer"),
        signed_at=_lookup(row, "signed_at"),
        reference=_lookup(row, "reference"),
        notes=_lookup(row, "notes"),
        row=index,
        raw=dict(row),
    )


def _json_payload(payload):
    if isinstance(payload, dict):
        for key in (
            "entries",
            "records",
            "items",
            "rows",
            "libraries",
            "符号库",
            "签收记录",
        ):
            if key in payload and isinstance(payload[key], (list, dict)):
                return payload[key]
        return [payload]
    return payload


def _rows_from_json(payload):
    payload = _json_payload(payload)
    if isinstance(payload, dict):
        # Mapping of display name -> attributes is common in small hand-written sheets.
        rows = []
        for name, value in payload.items():
            if isinstance(value, dict):
                row = dict(value)
                row.setdefault("name", name)
                rows.append(row)
            else:
                rows.append({"name": name, "digest": value})
        return rows
    if isinstance(payload, list):
        rows = []
        for item in payload:
            if isinstance(item, dict):
                rows.append(item)
            elif isinstance(item, str):
                rows.append({"name": item})
        return rows
    return []


def _parse_markdown_table(text):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    table_lines = [
        line for line in lines if line.startswith("|") and line.endswith("|")
    ]
    if len(table_lines) < 3:
        return []
    header = [cell.strip() for cell in table_lines[0].strip("|").split("|")]
    separator = [cell.strip() for cell in table_lines[1].strip("|").split("|")]
    if len(separator) != len(header) or not all(
        re.match(r"^:?-+:?$", cell.replace(" ", "")) for cell in separator
    ):
        return []
    rows = []
    for line in table_lines[2:]:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != len(header):
            continue
        rows.append(dict(zip(header, cells)))
    return rows


def _read_text(source):
    if hasattr(source, "read"):
        return source.read()
    if isinstance(source, (str, bytes, os.PathLike)):
        if isinstance(source, bytes):
            return source.decode("utf-8-sig", errors="replace")
        if os.path.exists(source):
            with open(source, "r", encoding="utf-8-sig", errors="replace") as handle:
                return handle.read()
        return source
    return None


def _rows_from_text(text, extension=None):
    stripped = text.lstrip()
    if (extension and extension.lower() == ".json") or stripped[:1] in ("{", "["):
        try:
            return _rows_from_json(json.loads(text))
        except json.JSONDecodeError:
            pass

    if (extension and extension.lower() in (".md", ".markdown")) or "|" in stripped:
        rows = _parse_markdown_table(text)
        if rows:
            return rows

    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = "\t" if "\t" in sample.splitlines()[0] else ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    rows = []
    for row in reader:
        if any(_clean_text(value) for value in row.values()):
            rows.append(dict(row))
    return rows


def _load_rows(source):
    if isinstance(source, (list, dict)):
        return _rows_from_json(source)
    if hasattr(source, "read"):
        text = source.read()
        if isinstance(text, bytes):
            text = text.decode("utf-8-sig", errors="replace")
        return _rows_from_text(text)
    if isinstance(source, (str, bytes, os.PathLike)):
        if isinstance(source, bytes):
            return _rows_from_text(source.decode("utf-8-sig", errors="replace"))
        if os.path.exists(source):
            extension = os.path.splitext(source)[1].lower()
            with open(source, "rb") as handle:
                text = handle.read().decode("utf-8-sig", errors="replace")
            return _rows_from_text(text, extension=extension)
        return _rows_from_text(source)
    return []


def load_signoff(source):
    """Load a JSON/CSV/TSV/Markdown sign-off sheet into ``SignoffEntry`` rows."""

    rows = _load_rows(source)
    entries = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        entry = _entry_from_row(row, index)
        if entry.name or entry.pdb_path or entry.digest or entry.pe_digest:
            entries.append(entry)
    return entries


def _claim_from_mapping(mapping, index):
    if not isinstance(mapping, dict):
        return Claim(display_name=_clean_text(mapping), ordinal=index, raw={})

    row = dict(mapping)
    source = row.get("source")
    if isinstance(source, dict):
        row.setdefault("source_file", source.get("file") or source.get("path"))
        row.setdefault("line", source.get("line"))

    display_name = (
        row.get("display_name")
        or row.get("name")
        or row.get("pdb_name")
        or row.get("pdb")
        or row.get("symbol")
        or _lookup(row, "name")
    )
    source_file = (
        row.get("source_file")
        or row.get("source")
        or row.get("file")
        or row.get("path")
        or row.get("源文件")
        or row.get("源代码文件")
    )
    if isinstance(source_file, dict):
        source_file = source_file.get("file") or source_file.get("path")
    line = row.get("line") or row.get("行号") or row.get("lineno")
    if line is None and isinstance(source_file, str):
        match = re.match(r"^(.*?):(\d+)$", source_file)
        if match and ("\\" in source_file or "/" in source_file):
            source_file = match.group(1)
            line = int(match.group(2))

    guid = _lookup(row, "guid") or row.get("pdb_guid") or row.get("GUID")
    age = _lookup(row, "age") or row.get("pdb_age") or row.get("Age")
    signature = _lookup(row, "signature") or row.get("pdb_signature")
    guid, age, signature = _decode_identity(guid, age, signature)
    digest_value = _lookup(row, "digest")
    pe_digest_value = _lookup(row, "pe_digest")

    consumed = {
        "display_name",
        "name",
        "source_file",
        "source",
        "file",
        "path",
        "line",
        "symbol",
        "address",
    }
    metadata = {key: value for key, value in row.items() if key not in consumed}
    return Claim(
        display_name=display_name,
        source_file=source_file,
        line=line,
        symbol=row.get("symbol") or row.get("函数") or row.get("符号"),
        address=row.get("address") or row.get("rva") or row.get("偏移"),
        pdb_path=row.get("pdb") or row.get("pdb_path") or row.get("symbol_library"),
        pdb_name=row.get("pdb_name"),
        guid=guid,
        age=age,
        signature=signature,
        digest=parse_digest(digest_value) if digest_value is not None else None,
        pe_digest=(
            parse_digest(pe_digest_value) if pe_digest_value is not None else None
        ),
        receipt=row.get("receipt") or row.get("signoff_ref") or row.get("签收单号"),
        record_id=row.get("record_id") or row.get("claim_id") or row.get("id"),
        ordinal=index,
        metadata=metadata,
        raw=dict(mapping),
    )


def claims_from_signoff(entries):
    """Build evaluable claims from sign-off rows when no claim file is given."""

    claims = []
    for index, entry in enumerate(entries, start=1):
        claims.append(
            Claim(
                display_name=entry.name or entry.pdb_name,
                pdb_path=entry.pdb_path,
                pdb_name=entry.pdb_name,
                guid=entry.guid,
                age=entry.age,
                signature=entry.signature,
                digest=entry.digest,
                pe_digest=entry.pe_digest,
                receipt=entry.reference,
                record_id="signoff-row-%04d" % (entry.row or index),
                ordinal=index,
                metadata={"generated_from": "signoff"},
                raw={},
            )
        )
    return claims


def load_claims(source):
    """Load source-location claims from JSON or a CSV/TSV table."""

    if source is None:
        return []
    if isinstance(source, dict):
        payload = source
        for key in (
            "claims",
            "source_location_claims",
            "records",
            "items",
            "源定位声明",
        ):
            if key in payload and isinstance(payload[key], list):
                payload = payload[key]
                break
        else:
            payload = [payload]
    elif isinstance(source, list):
        payload = source
    elif hasattr(source, "read"):
        text = source.read()
        if isinstance(text, bytes):
            text = text.decode("utf-8-sig", errors="replace")
        return _claims_from_rows(_rows_from_text(text))
    elif isinstance(source, (str, bytes, os.PathLike)):
        if isinstance(source, bytes):
            return _claims_from_rows(
                _rows_from_text(source.decode("utf-8-sig", errors="replace"))
            )
        if os.path.exists(source):
            extension = os.path.splitext(source)[1].lower()
            with open(source, "rb") as handle:
                text = handle.read().decode("utf-8-sig", errors="replace")
            if extension == ".json" or text.lstrip()[:1] in ("{", "["):
                return load_claims(json.loads(text))
            return _claims_from_rows(_rows_from_text(text, extension=extension))
        return _claims_from_rows(_rows_from_text(source))
    else:
        return []

    if isinstance(payload, dict):
        payload = [payload]
    return [
        _claim_from_mapping(item, index) for index, item in enumerate(payload, start=1)
    ]


def _claims_from_rows(rows):
    return [
        _claim_from_mapping(row, index)
        for index, row in enumerate(rows, start=1)
        if row is not None
    ]

"""MITRE ATT&CK (STIX bundle) -> techniques, tactics, groups, attack software and their links.

Deliberately ignored: retired entries (revoked or deprecated), mitigations, detections,
campaigns, and every field naming a person (`x_mitre_contributors`, authorship references).
"""

import json
import re
from typing import Any

from estran.collector.sdk import Connector, ConnectorError, LinkRecord, ObjectRecord, Translation

_OBJECT_TYPES = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "intrusion-set": "group",
    "malware": "software",
    "tool": "software",
}
# STIX "uses" relationship -> ontology link, by the types at both ends.
_USES = {
    ("group", "technique"): "group_uses_technique",
    ("group", "software"): "group_uses_software",
    ("software", "technique"): "software_uses_technique",
}
_PUBLIC_ID = re.compile(r"^(T\d{4}(\.\d{3})?|TA\d{4}|G\d{4}|S\d{4})$")
_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")


class AttackConnector(Connector):
    def translate(self, raw: bytes) -> Translation:
        try:
            bundle = json.loads(raw)
        except ValueError as error:
            raise ConnectorError(f"ATT&CK bundle is not valid JSON: {error}") from error
        items = bundle.get("objects") if isinstance(bundle, dict) else None
        if not isinstance(items, list):
            raise ConnectorError("ATT&CK bundle has no 'objects' list")

        objects: list[ObjectRecord] = []
        refs: dict[str, tuple[str, str]] = {}  # STIX id -> (ontology type, public id)
        tactic_of_phase: dict[str, str] = {}
        phases: dict[str, list[str]] = {}
        skipped = 0
        for item in items:
            if not isinstance(item, dict) or item.get("type") not in _OBJECT_TYPES:
                continue
            if item.get("revoked") or item.get("x_mitre_deprecated"):
                continue
            record = _object(item)
            if record is None:
                skipped += 1
                continue
            objects.append(record)
            refs[item["id"]] = (record.type, record.key)
            if record.type == "tactic" and isinstance(item.get("x_mitre_shortname"), str):
                tactic_of_phase[item["x_mitre_shortname"]] = record.key
            if record.type == "technique":
                phases[record.key] = [
                    str(phase["phase_name"])
                    for phase in item.get("kill_chain_phases") or []
                    if isinstance(phase, dict)
                    and phase.get("kill_chain_name") == "mitre-attack"
                    and isinstance(phase.get("phase_name"), str)
                ]

        links: dict[tuple[str, str, str], LinkRecord] = {}

        def add(type_id: str, source: tuple[str, str], target: tuple[str, str]) -> None:
            links.setdefault((type_id, source[1], target[1]), LinkRecord(type_id, source, target))

        for technique, names in phases.items():
            for name in names:
                if name in tactic_of_phase:
                    add(
                        "technique_in_tactic",
                        ("technique", technique),
                        ("tactic", tactic_of_phase[name]),
                    )

        for item in items:
            if not isinstance(item, dict) or item.get("type") != "relationship":
                continue
            if item.get("revoked") or item.get("x_mitre_deprecated"):
                continue
            source = refs.get(str(item.get("source_ref")))
            target = refs.get(str(item.get("target_ref")))
            if source is None or target is None:
                continue  # one end is retired or of a kind Estran does not keep
            kind = item.get("relationship_type")
            if kind == "uses" and (source[0], target[0]) in _USES:
                add(_USES[(source[0], target[0])], source, target)
            elif kind == "subtechnique-of" and source[0] == target[0] == "technique":
                add("subtechnique_of", source, target)

        return Translation(objects=objects, links=list(links.values()), skipped=skipped)


def _object(item: dict[str, Any]) -> ObjectRecord | None:
    reference = next(
        (
            ref
            for ref in item.get("external_references") or []
            if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"
        ),
        None,
    )
    name = item.get("name")
    if reference is None or not isinstance(name, str) or not name.strip():
        return None
    key = reference.get("external_id")
    if not isinstance(key, str) or not _PUBLIC_ID.match(key):
        return None

    type_id = _OBJECT_TYPES[item["type"]]
    name = name.strip()
    properties: dict[str, Any] = {"name": name, "description": _clean(item.get("description"))}
    url = reference.get("url")
    if isinstance(url, str) and url.startswith("https://attack.mitre.org/"):
        properties["url"] = url
    if type_id == "technique":
        properties["is_subtechnique"] = bool(item.get("x_mitre_is_subtechnique"))
    if type_id in ("technique", "software"):
        properties["platforms"] = _texts(item.get("x_mitre_platforms"))
    if type_id == "software":
        properties["kind"] = item["type"]
        properties["aliases"] = _texts(item.get("x_mitre_aliases"), without=name)
    if type_id == "group":
        properties["aliases"] = _texts(item.get("aliases"), without=name)
    properties = {k: v for k, v in properties.items() if v not in ("", [], None)}
    return ObjectRecord(type_id, key, name, properties)


def _clean(text: Any) -> str:
    """Drop the source's citation markers and markdown links; keep the prose."""
    if not isinstance(text, str):
        return ""
    text = _MARKDOWN_LINK.sub(r"\1", _CITATION.sub("", text))
    return re.sub(r"[ \t]+", " ", text).strip()


def _texts(value: Any, without: str | None = None) -> list[str]:
    if not isinstance(value, list):
        return []
    texts = [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return list(dict.fromkeys(text for text in texts if text != without))  # keeps the order

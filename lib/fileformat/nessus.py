"""Generic Tenable Nessus NessusClientData_v2 XML writer."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

_REPORT_ITEM_FIELDS = (
    "plugin_id",
    "plugin_name",
    "port",
    "protocol",
    "severity",
    "description",
    "plugin_output",
)


@dataclass(frozen=True)
class NessusHostTag:
    name: str
    value: str


@dataclass(frozen=True)
class NessusReportItem:
    plugin_id: str
    plugin_name: str
    port: str = "0"
    protocol: str = "tcp"
    severity: str = "0"
    description: str = ""
    plugin_output: str = ""
    fields: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class NessusReportHost:
    name: str
    tags: Sequence[NessusHostTag] = ()
    items: Sequence[NessusReportItem] = ()


@dataclass(frozen=True)
class NessusClientData:
    report_name: str
    hosts: Sequence[NessusReportHost]


def _append_text(parent: ET.Element, tag: str, text: str) -> None:
    element = ET.SubElement(parent, tag)
    element.text = text


def _write_report_item(parent: ET.Element, item: NessusReportItem) -> None:
    report_item = ET.SubElement(parent, "ReportItem")
    _append_text(report_item, "pluginID", item.plugin_id)
    _append_text(report_item, "pluginName", item.plugin_name)
    _append_text(report_item, "port", item.port)
    _append_text(report_item, "protocol", item.protocol)
    _append_text(report_item, "severity", item.severity)
    if item.description:
        _append_text(report_item, "description", item.description)
    if item.plugin_output:
        _append_text(report_item, "plugin_output", item.plugin_output)
    for key, value in item.fields.items():
        if key in _REPORT_ITEM_FIELDS:
            continue
        _append_text(report_item, key, value)


def write_nessus_client_data(output_path: Path | str, data: NessusClientData) -> Path:
    """Serialize NessusClientData_v2 XML to *output_path*."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    root = ET.Element("NessusClientData_v2")
    report = ET.SubElement(root, "Report")
    report.set("name", data.report_name)

    for host in data.hosts:
        report_host = ET.SubElement(report, "ReportHost")
        report_host.set("name", host.name)

        host_properties = ET.SubElement(report_host, "HostProperties")
        for tag in host.tags:
            tag_el = ET.SubElement(host_properties, "tag")
            tag_el.set("name", tag.name)
            tag_el.text = tag.value

        for item in host.items:
            _write_report_item(report_host, item)

    tree = ET.ElementTree(root)
    with open(out, "wb") as fh:
        tree.write(fh, encoding="utf-8", xml_declaration=True)
    return out.resolve()

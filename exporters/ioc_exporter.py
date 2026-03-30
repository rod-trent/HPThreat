"""Export IOCs in JSON, CSV, and STIX 2.1 formats."""

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from analysis.ioc_extractor import IOC
from config import GITHUB_REPO


class IOCExporter:
    def export_json(self, iocs: list[IOC]) -> str:
        return json.dumps([ioc.to_dict() for ioc in iocs], indent=2, default=str)

    def export_csv(self, iocs: list[IOC]) -> str:
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=["type", "value", "source", "first_seen", "last_seen", "count"],
            extrasaction="ignore",
        )
        writer.writeheader()
        for ioc in iocs:
            writer.writerow(ioc.to_dict())
        return output.getvalue()

    def export_stix(self, iocs: list[IOC], source_name: str) -> str:
        """Build a STIX 2.1 Bundle. Falls back to manual JSON if stix2 not installed."""
        try:
            return self._export_stix_with_lib(iocs, source_name)
        except ImportError:
            return self._export_stix_manual(iocs, source_name)

    def _export_stix_with_lib(self, iocs: list[IOC], source_name: str) -> str:
        import stix2

        identity = stix2.Identity(
            name="HPThreat",
            identity_class="system",
            description=f"HPThreat MCP Server honeypot: {source_name}. {GITHUB_REPO}",
        )

        objects = [identity]
        now = datetime.now(timezone.utc)

        for ioc in iocs:
            pattern = self._ioc_to_stix_pattern(ioc)
            if not pattern:
                continue
            try:
                indicator = stix2.Indicator(
                    name=f"{ioc.type}: {ioc.value[:80]}",
                    description=f"Observed {ioc.count}x by honeypot {ioc.source}",
                    indicator_types=["malicious-activity"],
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=ioc.first_seen or now.isoformat(),
                    created_by_ref=identity.id,
                    labels=[ioc.type],
                )
                objects.append(indicator)
            except Exception:
                continue

        bundle = stix2.Bundle(objects=objects, allow_custom=True)
        return bundle.serialize(pretty=True)

    def _export_stix_manual(self, iocs: list[IOC], source_name: str) -> str:
        now = datetime.now(timezone.utc).isoformat()
        identity_id = f"identity--{uuid.uuid4()}"
        stix_objects = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": identity_id,
                "created": now,
                "modified": now,
                "name": "HPThreat",
                "identity_class": "system",
                "description": f"HPThreat MCP Server. {GITHUB_REPO}",
            }
        ]
        for ioc in iocs:
            pattern = self._ioc_to_stix_pattern(ioc)
            if not pattern:
                continue
            indicator_id = f"indicator--{uuid.uuid4()}"
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": ioc.first_seen or now,
                "modified": ioc.last_seen or now,
                "created_by_ref": identity_id,
                "name": f"{ioc.type}: {ioc.value[:80]}",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ioc.first_seen or now,
                "labels": [ioc.type],
                "description": f"Observed {ioc.count}x by honeypot {ioc.source}",
            })
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": stix_objects,
        }
        return json.dumps(bundle, indent=2, default=str)

    @staticmethod
    def _ioc_to_stix_pattern(ioc: IOC) -> Optional[str]:
        if ioc.type == "ip":
            return f"[ipv4-addr:value = '{ioc.value}']"
        elif ioc.type == "hash_md5":
            return f"[file:hashes.MD5 = '{ioc.value}']"
        elif ioc.type == "hash_sha256":
            return f"[file:hashes.'SHA-256' = '{ioc.value}']"
        elif ioc.type == "url":
            safe = ioc.value.replace("'", "\\'")
            return f"[url:value = '{safe}']"
        elif ioc.type == "reverse_shell":
            parts = ioc.value.split(":", 1)
            if len(parts) == 2:
                return f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{parts[0]}']"
        return None

"""YARA, run on this instance against the submitted file.

Nothing leaves: the rules are local files and the scan runs in-process, so this
is the one file analyzer that is safe at TLP:RED and does not depend on the
instance being allowed to send samples to providers.

A rule match is a pattern hit, not a verdict. Community rules misfire, so one
matching rule is Suspicious and several distinct rules are Malicious. A file no
rule matches is Unknown: the loaded rules not recognising a sample says nothing
about whether it is clean.

Rules come from `custom/` (the operator's own) and from the public rulesets an
administrator pulled, see `app.services.yara_rules`.

Contract note: exercised against small local rule fixtures only; it has not
been run against a full community ruleset on real samples.
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services import yara_rules
from app.services.observables import Observable

_MAX_REPORTED = 50


def _describe(match: Any) -> dict[str, Any]:
    meta = match.meta if isinstance(match.meta, dict) else {}
    return {
        "rule": str(match.rule),
        "namespace": str(match.namespace),
        "tags": [str(tag) for tag in match.tags][:10],
        "description": str(meta.get("description", ""))[:200],
        "strings_matched": len(match.strings),
    }


@register
class YaraLocalAnalyzer(BaseAnalyzer):
    """Scans the submitted file with the rulesets mounted on this instance."""

    name = "yara_local"
    label = "YARA (local)"
    description = (
        "Scans the submitted file with your own and pulled YARA rulesets, on this instance."
    )
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.FILE,)
    options_schema: ClassVar[dict[str, Any]] = {
        "malicious_rules": {
            "type": "integer",
            "default": 3,
            "label": "Distinct matching rules from which the file is Malicious",
        },
    }
    provider = ProviderInfo(
        name="Local YARA",
        url="https://virustotal.github.io/yara/",
        api_base_url="(none: runs locally)",
        credential_url="",
        free_tier="Free; no account.",
        rate_limit="None; bounded by the analyzer timeout.",
        notes="The file is never sent anywhere. Rulesets are managed in Admin, YARA rules.",
    )
    max_tlp = Tlp.RED
    documentation_url = "https://yara.readthedocs.io/"
    free_tier = True
    default_timeout = 60
    default_cache_ttl = 3600
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        payload = self.local_sample_bytes()
        if payload is None:
            return self.skipped("YARA (local) scans a submitted file; no file came with this job.")

        # Compiling can take seconds on a large ruleset, and so can a scan, so
        # both stay off the event loop.
        compiled = await asyncio.to_thread(yara_rules.load)
        if compiled.rules is None:
            detail = f" ({compiled.problems[0]})" if compiled.problems else ""
            return self.failed(
                "No YARA rules are loaded. Pull a ruleset in Admin, YARA rules, or drop "
                f".yar files into the custom folder{detail}."
            )

        yara = yara_rules.get_yara()
        try:
            matches = await asyncio.to_thread(
                compiled.rules.match, data=payload, timeout=max(1, self.timeout - 5)
            )
        except yara.TimeoutError:
            return self.failed("The YARA scan timed out before every rule was tried.")
        except yara.Error as exc:
            return self.failed(f"The YARA scan failed: {str(exc)[:200]}")

        described = [_describe(match) for match in matches]
        raw = {
            "rules_files": compiled.files,
            "rule_files_with_errors": len(compiled.problems),
            "matches": described[:_MAX_REPORTED],
        }
        if not described:
            return self.ok(
                raw,
                PluginSummary(
                    verdict=Verdict.UNKNOWN,
                    headline=f"No match in {compiled.files} rule file(s).",
                    extra={"rule_files": compiled.files},
                ),
            )

        names = sorted({item["rule"] for item in described})
        threshold = int(self.option("malicious_rules", 3))
        verdict = Verdict.MALICIOUS if len(names) >= threshold else Verdict.SUSPICIOUS
        return self.ok(
            raw,
            PluginSummary(
                verdict=verdict,
                score=min(100, len(names) * 25),
                tags=["yara-match"],
                headline=f"{len(names)} YARA rule(s) match this file.",
                extra={"matched_rules": names[:_MAX_REPORTED], "rule_files": compiled.files},
            ),
        )

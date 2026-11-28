"""APK_Info: what an Android package asks for, read with Androguard on this instance.

Androguard parses the package in memory: the manifest, the permissions and the
declared components. Nothing is installed, run or decompiled, and the bytes never
leave the instance.

Verdict. A permission is a request, not an action, and most legitimate apps ask for
the sensitive ones. So a single permission is a tag at most. A combination that is
the usual shape of a banking trojan or a stalkerware install is Suspicious:
accessibility control together with overlay drawing, sideload installs, or SMS
interception. Nothing is Malicious from the manifest alone, and a package with no
such combination is Unknown, never Clean.

Contract note: the rule set is a starting list, not a corpus-tested detector. The
parser has been exercised against a stub and against non-APK input only, not against
a corpus of real packages.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.analyzer.file_info import MAX_FILE_BYTES, identify
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable

_PREFIX = "android.permission."
_PARSE_SECONDS = 60


@dataclass(frozen=True)
class Indicator:
    name: str
    severity: str  # "high" raises the verdict to Suspicious; "info" is a tag
    needs: tuple[str, ...]  # every permission listed must be requested
    any_of: tuple[str, ...] = ()  # and at least one of these, when given


INDICATORS: tuple[Indicator, ...] = (
    Indicator(
        "accessibility-overlay",
        "high",
        ("BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"),
    ),
    Indicator(
        "accessibility-control",
        "high",
        ("BIND_ACCESSIBILITY_SERVICE",),
        ("INTERNET", "RECEIVE_SMS", "REQUEST_INSTALL_PACKAGES"),
    ),
    Indicator(
        "sideload-install",
        "high",
        ("REQUEST_INSTALL_PACKAGES", "INTERNET"),
    ),
    Indicator(
        "sms-interception",
        "high",
        ("RECEIVE_SMS", "READ_SMS"),
    ),
    Indicator("sms-sending", "info", ("SEND_SMS",)),
    Indicator("accessibility-service", "info", ("BIND_ACCESSIBILITY_SERVICE",)),
    Indicator("device-admin", "info", ("BIND_DEVICE_ADMIN",)),
    Indicator("call-interception", "info", ("PROCESS_OUTGOING_CALLS",)),
    Indicator("location-tracking", "info", ("ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION")),
    Indicator("microphone-access", "info", ("RECORD_AUDIO",)),
    Indicator("boot-start", "info", ("RECEIVE_BOOT_COMPLETED",)),
)


def _short(permissions: set[str]) -> set[str]:
    return {p[len(_PREFIX) :] if p.startswith(_PREFIX) else p for p in permissions}


def matched_indicators(permissions: set[str]) -> list[Indicator]:
    names = _short(permissions)
    found: list[Indicator] = []
    for indicator in INDICATORS:
        if not all(p in names for p in indicator.needs):
            continue
        if indicator.any_of and not any(p in names for p in indicator.any_of):
            continue
        found.append(indicator)
    return found


@dataclass(frozen=True)
class Manifest:
    """The parts of an APK's manifest the assessment reads."""

    package: str
    permissions: set[str]
    activities: list[str]
    services: list[str]
    receivers: list[str]
    min_sdk: int | None
    target_sdk: int | None


def read_manifest(payload: bytes) -> Manifest:
    """Parse the package in memory. Raises on anything that is not a readable APK."""
    from androguard.core.apk import APK  # imported here: heavy, only needed when run

    apk = APK(payload, raw=True)
    return Manifest(
        package=str(apk.get_package() or ""),
        permissions={str(p) for p in apk.get_permissions()},
        activities=[str(a) for a in apk.get_activities()],
        services=[str(s) for s in apk.get_services()],
        receivers=[str(r) for r in apk.get_receivers()],
        min_sdk=_as_int(apk.get_min_sdk_version()),
        target_sdk=_as_int(apk.get_target_sdk_version()),
    )


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class ApkInfoAnalyzer(BaseAnalyzer):
    """Permissions and declared components of an Android package."""

    name = "apk_info"
    label = "APK_Info (Androguard)"
    description = (
        "Permissions and risky permission combinations of an Android package, read in memory "
        "with Androguard. The package is never installed or run."
    )
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.FILE,)
    reads_local_sample: ClassVar[bool] = True
    provider = ProviderInfo(
        name="Local Androguard",
        url="https://github.com/androguard/androguard",
        api_base_url="(none: runs locally)",
        credential_url="",
        free_tier="Free; no account.",
        rate_limit="None; bounded by the analyzer timeout.",
        notes=(
            "Reads the manifest only. The package is never installed, executed or decompiled, "
            "and it is never sent anywhere."
        ),
    )
    max_tlp = Tlp.RED
    documentation_url = "https://github.com/androguard/androguard"
    free_tier = True
    default_timeout = _PARSE_SECONDS
    default_cache_ttl = 3600
    maturity = "alpha"

    async def run(self, observable: Observable) -> PluginResult:
        payload = self.local_sample_bytes()
        if payload is None:
            return self.skipped("APK_Info reads a submitted file; no file came with this job.")
        if len(payload) > MAX_FILE_BYTES:
            return self.skipped(f"The file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB.")
        if identify(payload) != "zip":
            return self.skipped("APK_Info reads Android packages; this file is not a zip archive.")

        try:
            manifest = await asyncio.wait_for(
                asyncio.to_thread(read_manifest, payload), timeout=_PARSE_SECONDS
            )
        except Exception:  # Androguard raises a range of errors on hostile input
            return self.failed("The file is not a readable Android package.")

        if not manifest.permissions and not manifest.package:
            return self.failed("The package has no readable manifest.")

        found = matched_indicators(manifest.permissions)
        highs = [item for item in found if item.severity == "high"]
        tags = [item.name for item in found]
        verdict = Verdict.SUSPICIOUS if highs else Verdict.UNKNOWN
        score = min(100, 30 * len(highs) + 5 * (len(found) - len(highs))) if found else None

        raw: dict[str, Any] = {
            "package": manifest.package,
            "permissions": sorted(manifest.permissions),
            "activities": manifest.activities,
            "services": manifest.services,
            "receivers": manifest.receivers,
            "min_sdk": manifest.min_sdk,
            "target_sdk": manifest.target_sdk,
            "indicators": tags,
        }
        summary = PluginSummary(
            verdict=verdict,
            score=score,
            tags=tags,
            headline=(
                f"{len(highs)} high-severity and {len(found) - len(highs)} other "
                f"indicator(s); {len(manifest.permissions)} permission(s) requested by "
                f"{manifest.package or 'an unnamed package'}."
            ),
            extra={
                "package": manifest.package,
                "indicators": tags,
                "permission_count": len(manifest.permissions),
            },
        )
        return self.ok(raw, summary)

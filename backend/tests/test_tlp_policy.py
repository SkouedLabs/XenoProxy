"""TLP policy: which plugins may touch a RED job, and that nothing runs a sample.

The allowlist below is the decision, written down. Adding a plugin that claims
TLP:RED fails this test until someone reads why and adds it here on purpose.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest

from app.models.job import Tlp
from app.plugins import load_all
from app.plugins.base.registry import iter_plugins
from app.services import tlp

# Plugins that send nothing outside the deployment at TLP:RED, and why.
_RED_ALLOWED = {
    "yara_local": "scans the sample with local rules",
    "doc_info": "parses the document locally",
    "strings_info": "reads strings locally",
    "file_info": "reads headers locally",
    "capa": "reads the import table locally",
    "apk_info": "reads the manifest in memory with Androguard",
    "phone_info": "reads the numbering plans locally, no lookup",
    "crypto_taint": "reads a local sanctions list, no chain or provider lookup",
    "feodotracker": "downloads a public list; the observable is matched here",
    "joesandbox_enterprise": "the team's own appliance",
    "ai_assessment": "gated at run time: refuses a RED job for a non-private server",
    "llm_synthesizer": "same gate as ai_assessment, applied at run time",
    "domain_to_ip": "pivot, resolved locally",
    "url_to_domain": "pivot, parsed locally",
    "url_to_ip": "pivot, parsed locally",
}


def test_only_reviewed_plugins_claim_tlp_red() -> None:
    load_all()
    claiming = {cls.name for cls in iter_plugins() if cls.max_tlp is Tlp.RED}
    assert claiming == set(_RED_ALLOWED), (
        "a plugin changed its RED status; review whether it sends data out: "
        f"{sorted(claiming ^ set(_RED_ALLOWED))}"
    )


@pytest.mark.parametrize("name", ["dns", "nvd", "misp_export"])
def test_plugins_that_reach_outside_are_capped_at_amber(name: str) -> None:
    load_all()
    cls = next(c for c in iter_plugins() if c.name == name)
    assert cls.max_tlp is Tlp.AMBER


def test_no_plugin_can_start_a_process_or_evaluate_code() -> None:
    banned_calls = {"eval", "exec", "system", "popen", "Popen", "run", "call", "check_output"}
    banned_modules = {"subprocess", "pty", "ctypes"}
    app = Path(__file__).resolve().parent.parent / "app"
    # The file inspection reads submitted bytes too, so it is held to the same rule.
    sources = [
        *(app / "plugins").rglob("*.py"),
        app / "services" / "inspection.py",
        app / "services" / "file_identity.py",
    ]
    offenders: list[str] = []
    for path in sources:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {(node.module or "").split(".")[0]}
            else:
                names = set()
            if names & banned_modules:
                offenders.append(f"{path.name}:{node.lineno} imports {names & banned_modules}")
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
                    offenders.append(f"{path.name}:{node.lineno} calls {func.id}")
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id in {"os", "subprocess"}
                    and func.attr in banned_calls
                ):
                    offenders.append(f"{path.name}:{node.lineno} calls {func.value.id}.{func.attr}")
    assert offenders == []


def _resolves_to(monkeypatch: pytest.MonkeyPatch, *addresses: str) -> None:
    def fake(host: str, port: object, *a: object, **k: object) -> list[tuple]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (item, 0)) for item in addresses]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


async def test_a_private_server_is_internal(monkeypatch: pytest.MonkeyPatch) -> None:
    _resolves_to(monkeypatch, "10.0.0.5")
    assert await tlp.endpoint_is_internal("http://ollama.lan:11434")


async def test_a_public_or_mixed_server_is_not_internal(monkeypatch: pytest.MonkeyPatch) -> None:
    _resolves_to(monkeypatch, "104.18.1.1")
    assert not await tlp.endpoint_is_internal("https://openrouter.ai/api")
    _resolves_to(monkeypatch, "10.0.0.5", "104.18.1.1")
    assert not await tlp.endpoint_is_internal("https://mixed.example")


async def test_an_unresolvable_server_is_not_internal(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> list:
        raise socket.gaierror

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert not await tlp.endpoint_is_internal("http://nowhere.example")


async def test_red_is_refused_for_a_hosted_model_and_others_are_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolves_to(monkeypatch, "104.18.1.1")
    assert await tlp.inference_refusal(Tlp.RED, "https://openrouter.ai/api")
    assert await tlp.inference_refusal(Tlp.AMBER, "https://openrouter.ai/api") is None
    _resolves_to(monkeypatch, "192.168.1.9")
    assert await tlp.inference_refusal(Tlp.RED, "http://ollama.lan") is None


# -- Trusted internal services ------------------------------------------------


def test_the_trust_switch_only_lifts_a_plugin_that_declares_a_higher_cap() -> None:
    assert tlp.effective_cap(Tlp.AMBER, None, {"trusted_internal": True}) is Tlp.AMBER
    assert tlp.effective_cap(Tlp.AMBER, Tlp.RED, {}) is Tlp.AMBER
    assert tlp.effective_cap(Tlp.AMBER, Tlp.RED, {"trusted_internal": True}) is Tlp.RED


def test_only_reviewed_plugins_can_be_trusted_up_to_red() -> None:
    load_all()
    lifted = {cls.name for cls in iter_plugins() if cls.trusted_internal_max_tlp is not None}
    assert lifted == {"misp_export"}

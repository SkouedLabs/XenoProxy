"""The identity recorded for a submitted file is computed from its bytes alone."""

from __future__ import annotations

from app.services import file_identity


def test_hashes_match_known_vectors() -> None:
    profile = file_identity.describe(b"abc", submitted_name="abc.bin")

    assert profile["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert profile["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert profile["sha256"] == ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    assert profile["size"] == 3


def test_empty_file_has_the_empty_hashes() -> None:
    profile = file_identity.describe(b"", submitted_name=None)

    assert profile["sha256"] == ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert profile["kind"] == "unknown"
    assert profile["entropy"] == 0.0
    assert profile["magic_hex"] == ""
    assert profile["extension"] == ""
    assert profile["extension_mismatch"] is False


def test_pdf_is_recognised_from_its_magic_not_its_name() -> None:
    profile = file_identity.describe(b"%PDF-1.7\n1 0 obj\n", submitted_name="report.pdf")

    assert profile["kind"] == "pdf"
    assert profile["mime"] == "application/pdf"
    assert profile["extension"] == ".pdf"
    assert profile["extension_mismatch"] is False
    assert profile["magic_hex"].startswith("255044462d")


def test_a_non_pe_file_named_like_a_document_is_a_mismatch() -> None:
    profile = file_identity.describe(b"%PDF-1.7\n", submitted_name="invoice.exe")

    assert profile["kind"] == "pdf"
    assert profile["extension"] == ".exe"
    assert profile["extension_mismatch"] is True


def test_the_directory_part_of_a_submitted_name_is_ignored() -> None:
    assert file_identity.submitted_extension("C:\\Users\\x\\Desktop\\Setup.EXE") == ".exe"
    assert file_identity.submitted_extension("archive") == ""
    assert file_identity.submitted_extension(".hidden") == ""


def test_entropy_separates_uniform_bytes_from_repetitive_ones() -> None:
    assert file_identity.shannon_entropy(b"A" * 1024) == 0.0
    uniform = bytes(range(256)) * 4
    assert file_identity.shannon_entropy(uniform) == 8.0


def test_png_and_script_magic_are_detected() -> None:
    png = file_identity.describe(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8, submitted_name="a.png")
    script = file_identity.describe(b"#!/bin/sh\necho hi\n", submitted_name="run.sh")

    assert png["kind"] == "png" and png["extension_mismatch"] is False
    assert script["kind"] == "script" and script["extension_mismatch"] is False

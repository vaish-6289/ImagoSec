import subprocess

import forensics
from forensics import detect_suspicious_magic, scan_with_clamav


def test_detects_selected_marker_after_file_header():
    data = b"ordinary image-like bytes" + b"\x00" * 12 + b"MZ" + b"rest"
    assert detect_suspicious_magic(data) == ["Windows executable marker (MZ) at byte offset 38"]


def test_returns_empty_for_bytes_without_selected_markers():
    assert detect_suspicious_magic(b"image bytes without listed signatures") == []


def test_detects_archive_signature_inside_bytes():
    data = b"prefix" + b"PK\x03\x04" + b"suffix"
    assert detect_suspicious_magic(data) == ["ZIP/archive marker at byte offset 6"]


def test_clamav_reports_unavailable_when_not_installed(monkeypatch):
    monkeypatch.setattr(forensics.shutil, "which", lambda _: None)

    result = scan_with_clamav(b"image bytes")

    assert result["status"] == "unavailable"


def test_clamav_clean_result_scans_bytes_from_stdin(monkeypatch):
    monkeypatch.setattr(forensics.shutil, "which", lambda _: "/usr/bin/clamscan")
    calls = {}

    def fake_run(command, **kwargs):
        calls["command"] = command
        calls.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=b"stdin: OK\n", stderr=b"")

    monkeypatch.setattr(forensics.subprocess, "run", fake_run)
    image_bytes = b"image bytes"

    result = scan_with_clamav(image_bytes)

    assert result == {"status": "clean", "details": "stdin: OK"}
    assert calls["input"] == image_bytes
    assert calls["command"][-1] == "-"


def test_clamav_infection_and_scanner_errors_are_not_reported_clean(monkeypatch):
    monkeypatch.setattr(forensics.shutil, "which", lambda _: "/usr/bin/clamscan")
    outputs = iter([
        subprocess.CompletedProcess([], 1, stdout=b"stdin: Test-Signature FOUND\n", stderr=b""),
        subprocess.CompletedProcess([], 2, stdout=b"", stderr=b"database unavailable\n"),
    ])
    monkeypatch.setattr(forensics.subprocess, "run", lambda *args, **kwargs: next(outputs))

    threat = scan_with_clamav(b"infected test bytes")
    error = scan_with_clamav(b"image bytes")

    assert threat == {"status": "threat", "details": "stdin: Test-Signature FOUND"}
    assert error == {"status": "error", "details": "database unavailable"}


def test_clamav_timeout_is_reported_as_error(monkeypatch):
    monkeypatch.setattr(forensics.shutil, "which", lambda _: "/usr/bin/clamscan")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(forensics.subprocess, "run", timeout)

    assert scan_with_clamav(b"image bytes")["status"] == "error"

from forensics import detect_suspicious_magic


def test_detects_selected_marker_after_file_header():
    data = b"ordinary image-like bytes" + b"\x00" * 12 + b"MZ" + b"rest"
    assert detect_suspicious_magic(data) == ["Windows executable marker (MZ) at byte offset 38"]


def test_returns_empty_for_bytes_without_selected_markers():
    assert detect_suspicious_magic(b"image bytes without listed signatures") == []


def test_detects_archive_signature_inside_bytes():
    data = b"prefix" + b"PK\x03\x04" + b"suffix"
    assert detect_suspicious_magic(data) == ["ZIP/archive marker at byte offset 6"]

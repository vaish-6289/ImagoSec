import hashlib
import io

import numpy as np
from PIL import Image, ExifTags


# These are triage indicators only. A byte-signature match does not establish that
# a file is malware, and a missing match does not establish that it is safe.
SUSPICIOUS_FILE_SIGNATURES = (
    (b"MZ", "Windows executable marker (MZ)"),
    (b"\x7fELF", "ELF executable marker"),
    (b"PK\x03\x04", "ZIP/archive marker"),
    (b"Rar!", "RAR/archive marker"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip/archive marker"),
)


def compute_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def detect_suspicious_magic(file_bytes):
    """Find selected executable/archive byte markers anywhere in a file.

    This is a lightweight triage check, not malware detection. Searching the full
    file can surface appended or embedded markers, but can also produce false
    positives when those bytes occur in ordinary image data.
    """
    matches = []
    for signature, label in SUSPICIOUS_FILE_SIGNATURES:
        offset = file_bytes.find(signature)
        if offset != -1:
            matches.append(f"{label} at byte offset {offset}")
    return matches


def validate_image_extension(filename, file_bytes):
    name = (filename or "").lower()
    allowed_exts = (".jpg", ".jpeg", ".png", ".bmp")
    ext_ok = name.endswith(allowed_exts)
    magic_matches = detect_suspicious_magic(file_bytes)

    if not ext_ok:
        return False, "File extension is not an allowed image type."
    if magic_matches:
        return False, "Selected executable/archive signature marker(s) found: " + "; ".join(magic_matches)
    return True, "Allowed extension and no selected executable/archive marker found."


def extract_metadata(file_bytes):
    try:
        image = Image.open(io.BytesIO(file_bytes))
        exif = image.getexif()
        metadata = {
            "format": image.format,
            "size": image.size,
            "mode": image.mode,
            "software": None,
            "flags": [],
        }

        if exif:
            for tag_id, value in exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                if tag_name == "Software":
                    metadata["software"] = str(value)
                if tag_name in ["Software", "Artist", "CameraOwnerName", "GPSInfo", "MakerNote"]:
                    metadata["flags"].append(tag_name)

        return metadata
    except Exception as exc:
        return {"error": str(exc)}


def calculate_ela_risk(file_bytes):
    try:
        image = Image.open(io.BytesIO(file_bytes)).convert("RGB")
        original = np.array(image, dtype=np.int16)

        scores = []
        for quality in [90, 75, 60]:
            buffer = io.BytesIO()
            image.save(buffer, format="JPEG", quality=quality)
            recompressed = Image.open(io.BytesIO(buffer.getvalue())).convert("RGB")
            diff = np.abs(original - np.array(recompressed, dtype=np.int16))
            scores.append(float(diff.mean()))

        avg_score = float(np.mean(scores))
        risk_score = min(100, int(avg_score * 2.5))

        return {
            "risk_score": risk_score,
            "quality_scores": [round(value, 3) for value in scores],
            "message": (
                "High pixel-difference indicator. This is not proof of manipulation."
                if risk_score > 60
                else "Some pixel differences detected; these can also result from normal recompression."
                if risk_score > 25
                else "Low pixel differences under this heuristic; this does not prove the image is unchanged."
            ),
        }
    except Exception as exc:
        return {"risk_score": 0, "quality_scores": [], "message": f"ELA not available: {str(exc)}"}


def analyze_image(filename, file_bytes):
    valid, validation_msg = validate_image_extension(filename, file_bytes)
    risk_score = 0
    issues = []
    suspicious_markers = detect_suspicious_magic(file_bytes)

    if not valid:
        issues.append(validation_msg)
        risk_score += 60
    if suspicious_markers:
        issues.extend(suspicious_markers)

    metadata = extract_metadata(file_bytes)
    if "error" not in metadata:
        if metadata.get("software"):
            issues.append(f"Editing software recorded in metadata: {metadata['software']}")
            risk_score += 20
        if metadata.get("flags"):
            issues.append(f"Metadata fields present: {metadata['flags']}")
            risk_score += 15

    ela = calculate_ela_risk(file_bytes)
    if ela["risk_score"] > 30:
        issues.append(f"ELA-style pixel difference indicator: {ela['message']}")
        risk_score += ela["risk_score"] // 2

    risk_score = min(100, risk_score)

    return {
        "valid": valid,
        "risk_score": risk_score,
        "issues": issues,
        "metadata": metadata,
        "ela": ela,
        "suspicious_markers": suspicious_markers,
        "sha256": compute_sha256(file_bytes),
    }


# Compatibility with existing imports/callers.
def _self_test_placeholder():
    return None

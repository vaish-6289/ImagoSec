import hashlib
import io

import numpy as np
from PIL import Image, ExifTags


def compute_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def detect_suspicious_magic(file_bytes):
    suspicious_signatures = [
        b"MZ",
        b"\x7fELF",
        b"PK\x03\x04",
        b"Rar!",
    ]

    matches = []
    for signature in suspicious_signatures:
        if signature in file_bytes[:512]:
            matches.append(signature.decode("latin1", errors="ignore"))
    return matches


def validate_image_extension(filename, file_bytes):
    name = (filename or "").lower()
    allowed_exts = [".jpg", ".jpeg", ".png", ".bmp"]
    ext_ok = any(name.endswith(ext) for ext in allowed_exts)

    magic_matches = detect_suspicious_magic(file_bytes)

    if not ext_ok:
        return False, "File extension is not an allowed image type."
    if magic_matches:
        return False, f"Suspicious file signature detected: {magic_matches}"
    return True, "Valid image file."


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
                "High manipulation risk detected."
                if risk_score > 60
                else "Low-to-medium risk observed."
                if risk_score > 25
                else "No obvious manipulation signal."
            ),
        }
    except Exception as exc:
        return {"risk_score": 0, "quality_scores": [], "message": f"ELA not available: {str(exc)}"}


def analyze_image(filename, file_bytes):
    valid, validation_msg = validate_image_extension(filename, file_bytes)
    risk_score = 0
    issues = []

    if not valid:
        issues.append(validation_msg)
        risk_score += 60

    metadata = extract_metadata(file_bytes)
    if "error" not in metadata:
        if metadata.get("software"):
            issues.append(f"Editing software detected: {metadata['software']}")
            risk_score += 20
        if metadata.get("flags"):
            issues.append(f"Metadata flags found: {metadata['flags']}")
            risk_score += 15

    ela = calculate_ela_risk(file_bytes)
    if ela["risk_score"] > 30:
        issues.append(f"ELA anomaly: {ela['message']}")
        risk_score += ela["risk_score"] // 2

    risk_score = min(100, risk_score)

    return {
        "valid": valid,
        "risk_score": risk_score,
        "issues": issues,
        "metadata": metadata,
        "ela": ela,
        "sha256": compute_sha256(file_bytes),
    }

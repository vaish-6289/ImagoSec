import hashlib
import io
import os

import numpy as np
from PIL import Image, ExifTags


def compute_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def detect_suspicious_magic(file_bytes: bytes):
    suspicious_signatures = [
        b"MZ",
        b"\x7fELF",
        b"PK\x03\x04",
        b"Rar!",
        b"7z\xbc\xaf\x27\x1c",
    ]
    matches = []
    for signature in suspicious_signatures:
        if signature in file_bytes[:512]:
            matches.append(signature.decode("latin1", errors="ignore"))
    return matches


def sanitize_image(file_bytes: bytes) -> bytes:
    try:
        image = Image.open(io.BytesIO(file_bytes))
        if image.mode in ("RGBA", "LA", "P"):
            image = image.convert("RGB")
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=95, optimize=True)
        return buffer.getvalue()
    except Exception:
        return b""


def validate_image_extension(filename: str, file_bytes: bytes):
    name = (filename or "").lower()
    allowed_exts = [".jpg", ".jpeg", ".png", ".bmp"]
    ext_ok = any(name.endswith(ext) for ext in allowed_exts)
    magic_matches = detect_suspicious_magic(file_bytes)

    if not ext_ok:
        return False, "File extension is not an allowed image type."
    if magic_matches:
        return False, f"Suspicious file signature detected: {magic_matches}"

    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            image.verify()
    except Exception:
        return False, "The uploaded file is not a readable image." 

    return True, "Valid image file."


def extract_metadata(file_bytes: bytes):
    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            exif = image.getexif()
            metadata = {
                "format": image.format,
                "size": image.size,
                "mode": image.mode,
                "software": None,
                "flags": [],
                "dpi": image.info.get("dpi"),
                "color_mode": image.mode,
            }

            if exif:
                for tag_id, value in exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    value_str = str(value)
                    if tag_name == "Software" and value_str:
                        metadata["software"] = value_str
                    if tag_name in [
                        "Software",
                        "Artist",
                        "CameraOwnerName",
                        "GPSInfo",
                        "MakerNote",
                        "DateTime",
                        "Model",
                    ]:
                        metadata["flags"].append(tag_name)

            if image.info.get("software"):
                metadata["software"] = str(image.info["software"])
                metadata["flags"].append("Software")

            metadata["flags"] = sorted(set(metadata["flags"]))
            return metadata
    except Exception as exc:
        return {"error": str(exc)}


def calculate_ela_risk(file_bytes: bytes):
    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            image = image.convert("RGB")
            original = np.array(image, dtype=np.float32)

            scores = []
            for quality in [95, 80, 65]:
                buffer = io.BytesIO()
                image.save(buffer, format="JPEG", quality=quality)
                recompressed = Image.open(io.BytesIO(buffer.getvalue())).convert("RGB")
                diff = np.abs(original - np.array(recompressed, dtype=np.float32))
                scores.append(float(diff.mean()))

            avg_score = float(np.mean(scores))
            risk_score = min(100, int(avg_score * 0.65))

            if risk_score >= 70:
                message = "High manipulation risk detected."
                status = "high"
            elif risk_score >= 35:
                message = "Moderate risk observed. Review the image closely."
                status = "moderate"
            else:
                message = "No obvious manipulation signal."
                status = "low"

            return {
                "risk_score": risk_score,
                "quality_scores": [round(value, 3) for value in scores],
                "message": message,
                "status": status,
            }
    except Exception as exc:
        return {
            "risk_score": 0,
            "quality_scores": [],
            "message": f"ELA not available: {str(exc)}",
            "status": "unavailable",
        }


def analyze_image(filename: str, file_bytes: bytes):
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
    if ela["risk_score"] > 20:
        issues.append(f"ELA anomaly: {ela['message']}")
        risk_score += max(0, ela["risk_score"] // 2)

    risk_score = min(100, risk_score)
    sanitized = sanitize_image(file_bytes)

    return {
        "valid": valid,
        "risk_score": risk_score,
        "issues": issues,
        "metadata": metadata,
        "ela": ela,
        "sha256": compute_sha256(file_bytes),
        "sanitized_image": sanitized if sanitized else None,
    }


# End of file

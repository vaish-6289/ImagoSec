import hashlib
import io

import numpy as np
from PIL import Image, ExifTags


SUSPICIOUS_FILE_SIGNATURES = (
    (b"MZ", "Windows executable marker (MZ)"),
    (b"\x7fELF", "ELF executable marker"),
    (b"PK\x03\x04", "ZIP/archive marker"),
    (b"Rar!", "RAR/archive marker"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip/archive marker"),
)

IMAGE_EXTENSIONS = {
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".png": "PNG",
    ".bmp": "BMP",
}


def compute_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def detect_suspicious_magic(file_bytes):
    matches = []
    for signature, label in SUSPICIOUS_FILE_SIGNATURES:
        start = 0
        while True:
            offset = file_bytes.find(signature, start)
            if offset < 0:
                break
            location = "at file start" if offset == 0 else f"embedded/appended at byte {offset}"
            matches.append(f"{label} ({location})")
            start = offset + 1
    return matches


def inspect_image_format(filename, file_bytes):
    suffix = ""
    if filename:
        import os
        suffix = os.path.splitext(filename.lower())[1]
    expected_format = IMAGE_EXTENSIONS.get(suffix)
    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            actual_format = image.format
            image.verify()
    except Exception as exc:
        return {
            "readable_image": False,
            "actual_format": None,
            "extension_mismatch": False,
            "message": f"Could not decode as a supported image: {exc}",
        }
    mismatch = expected_format is not None and actual_format != expected_format
    return {
        "readable_image": True,
        "actual_format": actual_format,
        "extension_mismatch": mismatch,
        "message": (
            f"Filename extension suggests {expected_format}, but file content is {actual_format}."
            if mismatch else f"File content is readable as {actual_format}."
        ),
    }


def detect_trailing_image_data(file_bytes, image_format):
    if image_format == "JPEG":
        end = file_bytes.rfind(b"\xff\xd9")
        if end >= 0:
            trailing_start = end + 2
            trailing = file_bytes[trailing_start:]
            return {"trailing_bytes": len(trailing), "offset": trailing_start} if trailing else None
    elif image_format == "PNG":
        end = file_bytes.rfind(b"\x00\x00\x00\x00IEND\xaeB`\x82")
        if end >= 0:
            trailing_start = end + 12
            trailing = file_bytes[trailing_start:]
            return {"trailing_bytes": len(trailing), "offset": trailing_start} if trailing else None
    return None


def validate_image_extension(filename, file_bytes):
    suffix = ""
    if filename:
        import os
        suffix = os.path.splitext(filename.lower())[1]
    if suffix not in IMAGE_EXTENSIONS:
        return False, "File extension is not an allowed image type."
    marker_matches = detect_suspicious_magic(file_bytes)
    if marker_matches:
        return False, "Selected executable/archive marker(s) found: " + "; ".join(marker_matches)
    return True, "Allowed image extension and no selected marker found."


def extract_metadata(file_bytes):
    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
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


def generate_ela_heatmap(file_bytes):
    try:
        image = Image.open(io.BytesIO(file_bytes)).convert("RGB")
        original = np.array(image, dtype=np.int16)
        scores = []
        for quality in [90, 75, 60]:
            buffer = io.BytesIO()
            image.save(buffer, format="JPEG", quality=quality)
            recompressed = Image.open(io.BytesIO(buffer.getvalue())).convert("RGB")
            diff = np.abs(original - np.array(recompressed, dtype=np.int16))
            scores.append(diff)
        diff_map = np.mean(np.stack(scores, axis=0), axis=0)
        normalized = np.clip((diff_map / max(1.0, diff_map.max())) * 255, 0, 255).astype(np.uint8)
        heat = np.stack([
            np.clip(normalized, 0, 255),
            np.clip(255 - normalized, 0, 255),
            np.full(normalized.shape, 80, dtype=np.uint8),
        ], axis=-1)
        heat = np.clip(heat, 0, 255).astype(np.uint8)
        return Image.fromarray(heat, mode="RGB")
    except Exception:
        return None


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
                "High pixel-difference indicator; not proof of manipulation."
                if risk_score > 60 else
                "Some pixel differences; these can also result from normal recompression."
                if risk_score > 25 else
                "Low pixel differences under this heuristic; this does not prove the image is unchanged."
            ),
            "heatmap": generate_ela_heatmap(file_bytes),
        }
    except Exception as exc:
        return {"risk_score": 0, "quality_scores": [], "message": f"ELA not available: {exc}", "heatmap": None}


def analyze_image(filename, file_bytes):
    marker_matches = detect_suspicious_magic(file_bytes)
    format_check = inspect_image_format(filename, file_bytes)
    valid, validation_msg = validate_image_extension(filename, file_bytes)
    issues = []

    if not format_check["readable_image"]:
        issues.append(format_check["message"])
    if format_check["extension_mismatch"]:
        issues.append(format_check["message"])
    if marker_matches:
        issues.extend(marker_matches)
    if not valid:
        issues.append(validation_msg)

    metadata = extract_metadata(file_bytes)
    if "error" not in metadata:
        if metadata.get("software"):
            issues.append(f"Editing software recorded in metadata: {metadata['software']}")
        if metadata.get("flags"):
            issues.append(f"Metadata fields present: {metadata['flags']}")

    ela = calculate_ela_risk(file_bytes) if format_check["readable_image"] else {"risk_score": 0, "quality_scores": [], "message": "Not available because the file could not be decoded as an image.", "heatmap": None}
    trailing_data = detect_trailing_image_data(file_bytes, format_check["actual_format"]) if format_check["actual_format"] else None
    if trailing_data:
        issues.append(f"Data found after the normal {format_check['actual_format']} end marker: {trailing_data['trailing_bytes']} bytes starting at byte {trailing_data['offset']}.")

    return {
        "valid": valid and format_check["readable_image"] and not format_check["extension_mismatch"],
        "risk_score": min(100, max(0, (60 if not valid else 0) + (20 if metadata.get("software") else 0) + (15 if metadata.get("flags") else 0) + max(0, ela.get("risk_score", 0) // 2))),
        "issues": issues,
        "metadata": metadata,
        "ela": ela,
        "suspicious_markers": marker_matches,
        "format_check": format_check,
        "trailing_data": trailing_data,
        "sha256": compute_sha256(file_bytes),
    }

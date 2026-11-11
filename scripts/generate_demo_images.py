"""Generate benign ImagoSec demo fixtures for local scanner behavior checks.

Run from the repository root:
    python scripts/generate_demo_images.py

All files are synthetic and harmless. `attack.jpg` is plain text containing the
literal marker `MZ` so the prototype's marker rule can be exercised; it is not an
executable or malware sample. The JPEG samples demonstrate metadata/pixel checks,
not camera authenticity or proof of manipulation.
"""

from pathlib import Path

from PIL import Image, ImageDraw

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "demo_images"
OUTPUT_DIR.mkdir(exist_ok=True)


def make_attack_fixture():
    # Benign text, deliberately given an image extension. The literal MZ prefix
    # exercises the current lightweight signature-marker rule without malware.
    content = (
        "MZ - IMAGOSEC SAFE TEST FIXTURE\n"
        "This is plain text, not an executable and not malware.\n"
        "It is named .jpg only to test extension/content mismatch handling.\n"
    )
    (OUTPUT_DIR / "attack.jpg").write_text(content, encoding="utf-8")


def make_camera_baseline():
    # Synthetic neutral color test image; it is not a real camera capture.
    image = Image.new("RGB", (640, 420), (113, 143, 168))
    draw = ImageDraw.Draw(image)
    draw.text((24, 24), "SYNTHETIC BASELINE — NOT A CAMERA ORIGINAL", fill=(242, 246, 250))
    image.save(OUTPUT_DIR / "authentic_camera.jpg", "JPEG", quality=95, optimize=False)


def make_edited_invoice_fixture():
    # Synthetic invoice with a visible changed amount block and a demo-only
    # metadata Software field. This does not claim Adobe/GIMP edited the file.
    image = Image.new("RGB", (900, 600), "white")
    draw = ImageDraw.Draw(image)
    draw.text((50, 35), "SYNTHETIC DEMO INVOICE — NOT A REAL BILL", fill="#1f2937")
    draw.line((50, 75, 850, 75), fill="#64748b", width=3)
    draw.text((55, 110), "Example School · Fee Statement", fill="#334155")
    draw.text((55, 170), "Student: Demo Student", fill="#334155")
    draw.text((55, 215), "Reference: DEMO-0001", fill="#334155")
    draw.text((55, 300), "Original total: $120.00", fill="#334155")
    # High-contrast synthetic edited region for visual demonstration.
    draw.rectangle((430, 275, 800, 370), fill="#fff1a8", outline="#d97706", width=4)
    draw.text((455, 310), "DEMO CHANGE: $1,200.00", fill="#b91c1c")
    draw.text((55, 520), "All names, amounts, and details are fictional.", fill="#64748b")

    exif = Image.Exif()
    exif[305] = "ImagoSec Synthetic Demo Editor"
    image.save(
        OUTPUT_DIR / "edited_invoice.jpg",
        "JPEG",
        quality=95,
        exif=exif,
    )


if __name__ == "__main__":
    make_attack_fixture()
    make_camera_baseline()
    make_edited_invoice_fixture()
    print(f"Created harmless demo fixtures in: {OUTPUT_DIR}")

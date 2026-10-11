"""
vision.py - screenshot handling (DEMONSTRATION MODE)

What is REAL in this file:
  * safe upload validation (only real PNG / JPEG images are accepted)
  * basic image facts: size, format, brightness, dominant colours

What is NOT real yet:
  * run_vision_language_model() is only a placeholder. To make the project
    truly multimodal, connect a vision-language model (for example CLIP)
    inside that function.
"""
import os
import uuid

from PIL import Image, ImageStat, UnidentifiedImageError

ALLOWED_FORMATS = {"PNG": ".png", "JPEG": ".jpg"}
MAX_PIXELS = 25_000_000          # reject absurdly large images
VLM_CONNECTED = False            # change to True after you integrate a real model


def save_screenshot(file_storage, upload_dir):
    """Validate an uploaded screenshot and save it under a random name.

    The file is never executed or rendered as HTML; it is only opened as an
    image. Returns (filename, full_path). Raises ValueError for bad files.
    """
    name = (file_storage.filename or "").lower()
    if not name.endswith((".png", ".jpg", ".jpeg")):
        raise ValueError("Only PNG and JPG screenshots are supported.")
    try:
        img = Image.open(file_storage.stream)
        if img.width * img.height > MAX_PIXELS:
            raise ValueError("The image is too large. Please upload a smaller screenshot.")
        fmt = img.format
        img.verify()                      # checks the file really is an image
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise ValueError("The uploaded file is not a valid image.")
    if fmt not in ALLOWED_FORMATS:
        raise ValueError("Only PNG and JPG screenshots are supported.")

    file_storage.stream.seek(0)
    filename = uuid.uuid4().hex + ALLOWED_FORMATS[fmt]
    path = os.path.join(upload_dir, filename)
    file_storage.save(path)
    return filename, path


def analyze_screenshot(path):
    """Return simple, genuine facts about the screenshot image."""
    with Image.open(path) as img:
        width, height = img.size
        fmt = img.format
        rgb = img.convert("RGB")

    small = rgb.resize((80, 80))
    brightness = round(ImageStat.Stat(small.convert("L")).mean[0])

    # Dominant colours: reduce the picture to 5 colours and count pixels
    quant = small.quantize(colors=5)
    palette = quant.getpalette() or []
    colors = []
    for count, index in sorted(quant.getcolors(), reverse=True):
        r, g, b = palette[index * 3: index * 3 + 3]
        colors.append({"hex": "#%02x%02x%02x" % (r, g, b),
                       "percent": round(count / (80 * 80) * 100)})

    observations = []
    if width < 500 or height < 300:
        observations.append("The screenshot has a low resolution, so fine details such as logos may be hard to inspect.")
    if brightness < 50:
        observations.append("The screenshot is very dark overall.")
    elif brightness > 215:
        observations.append("The screenshot is very bright overall (mostly white background).")
    if not observations:
        observations.append("No problems were found with the image quality.")

    return {
        "width": width, "height": height, "format": fmt,
        "size_kb": round(os.path.getsize(path) / 1024, 1),
        "brightness": brightness, "colors": colors,
        "observations": observations,
        "vlm_connected": VLM_CONNECTED,
    }


def run_vision_language_model(path, page_text=""):
    """PLACEHOLDER for your real vision-language model.

    Plug in a model here (for example CLIP) and return a dictionary such as:
        {"brand": "PayPal", "has_login_form": True, "score": 0.87}
    Until then it returns None and the report says that no model was used.
    """
    return None
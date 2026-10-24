"""Image metadata (EXIF) module."""

from __future__ import annotations
from typing import Any, Dict, Union


def scan_image(path: str, raw: bool = False) -> Union[str, Dict[str, Any]]:
    clean = path.strip()
    if not clean:
        err = "[!] Please provide an image file path."
        return {"error": err} if raw else err

    try:
        from PIL import Image, ExifTags
    except Exception as exc:
        err = f"[!] Pillow not available: {exc}"
        return {"error": err} if raw else err

    try:
        img = Image.open(clean)
    except Exception as exc:
        err = f"[!] Cannot open image: {exc}"
        return {"error": err} if raw else err

    exif_data = {}
    gps_coords = None
    try:
        exif = img._getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                exif_data[str(tag)] = value
            # GPS
            gps_tag = None
            for tag_id, tag_name in ExifTags.TAGS.items():
                if tag_name == "GPSInfo":
                    gps_tag = tag_id
                    break
            if gps_tag and gps_tag in exif:
                gps = exif[gps_tag]
                # convert
                def _conv(v):
                    try:
                        return float(v[0]) + float(v[1]) / 60.0 + float(v[2]) / 3600.0
                    except Exception:
                        return None
                # gps dict keys 1=N/S,2=lat,3=E/W,4=lon
                lat = _conv(gps.get(2)) if isinstance(gps, dict) else None
                lon = _conv(gps.get(4)) if isinstance(gps, dict) else None
                if lat is not None and lon is not None:
                    if gps.get(1) == "S":
                        lat = -lat
                    if gps.get(3) == "W":
                        lon = -lon
                    gps_coords = (lat, lon)
    except Exception:
        pass

    data = {
        "file": clean,
        "format": img.format,
        "size": img.size,
        "exif": {k: (str(v) if not isinstance(v, (int, float, str)) else v) for k, v in exif_data.items()},
        "gps": gps_coords,
        "reverse_search_links": [
            "https://lens.google.com/uploadbyurl",
            "https://tineye.com/",
            "https://yandex.com/images/",
        ],
    }
    if raw:
        return data

    from karagargha.core import colors
    lines = [colors.found(f"Image metadata for {clean}:")]
    lines.append(f"  • Format: {img.format}")
    lines.append(f"  • Size: {img.size[0]}x{img.size[1]}")
    if exif_data:
        lines.append("  • EXIF:")
        for k, v in list(exif_data.items())[:40]:
            lines.append(f"      {k}: {v}")
    else:
        lines.append("  • EXIF: none")
    if gps_coords:
        lines.append(f"  • GPS Coordinates: {gps_coords[0]}, {gps_coords[1]}")
        lines.append(f"    Google Maps: https://www.google.com/maps?q={gps_coords[0]},{gps_coords[1]}")
    else:
        lines.append("  • GPS: not found")
    lines.append("  • Reverse image search (manual): Google Lens, TinEye, Yandex.")
    return "\n".join(lines)

"""Phone Number Intelligence Module for KaraQargha.

Performs phone number validation, E.164 normalization, carrier identification,
region geolocation, and timezone discovery using the phonenumbers library.
"""

from __future__ import annotations

from typing import Any, Dict, Union


def scan_phone(
    phone_number: str,
    raw: bool = False,
) -> Union[str, Dict[str, Any]]:
    """Lookup phone number metadata, carrier, region, timezone, and E.164 format.

    Args:
        phone_number: Raw phone number string (preferably with leading +).
        raw: If True, returns structured dictionary instead of formatted string.

    Returns:
        Plain formatted string with phone details, or dictionary if raw=True.
    """
    clean_number = phone_number.strip()
    if not clean_number:
        err = "[!] Please provide a phone number to lookup."
        return {"error": err} if raw else err

    try:
        # Lazy imports inside function
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone
        from karagargha.core import colors
    except ImportError as imp_err:
        err = f"[!] phonenumbers library is not installed ({imp_err}). Run: pip install phonenumbers"
        return {"error": err} if raw else err

    try:
        # Handle phone number parsing with auto country detection
        candidate = clean_number if clean_number.startswith("+") else f"+{clean_number}"
        try:
            parsed = phonenumbers.parse(candidate, None)
        except phonenumbers.NumberParseException:
            # Retry parsing original without leading plus if it fails
            parsed = phonenumbers.parse(clean_number, None)

        is_valid = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)

        e164_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nat_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

        region_desc = geocoder.description_for_number(parsed, "en") or "Unknown"
        carrier_name = carrier.name_for_number(parsed, "en") or "Unknown"
        tz_list = list(timezone.time_zones_for_number(parsed))
        tz_desc = ", ".join(tz_list) if tz_list else "Unknown"

        number_type_enum = phonenumbers.number_type(parsed)
        type_names = {
            0: "FIXED_LINE",
            1: "MOBILE",
            2: "FIXED_LINE_OR_MOBILE",
            3: "TOLL_FREE",
            4: "PREMIUM_RATE",
            5: "SHARED_COST",
            6: "VOIP",
            7: "PERSONAL_NUMBER",
            8: "PAGER",
            9: "UAN",
            10: "VOICEMAIL",
        }
        line_type = type_names.get(number_type_enum, "UNKNOWN")

        data: Dict[str, Any] = {
            "input": phone_number,
            "valid": is_valid,
            "possible": is_possible,
            "e164": e164_format,
            "international": intl_format,
            "national": nat_format,
            "country_code": parsed.country_code,
            "region": region_desc,
            "carrier": carrier_name,
            "timezone": tz_list,
            "line_type": line_type,
        }

        if raw:
            return data

        valid_badge = colors.colorize("Valid", "green", bright=True) if is_valid else colors.colorize("Invalid / Unverified", "red")

        lines = [
            colors.found(f"Phone Lookup Results for {clean_number}:"),
            f"  • Status:         {valid_badge}",
            f"  • E.164 Format:   {e164_format}",
            f"  • International:  {intl_format}",
            f"  • National:       {nat_format}",
            f"  • Region/City:    {region_desc}",
            f"  • Carrier:        {carrier_name}",
            f"  • Timezone(s):    {tz_desc}",
            f"  • Line Type:      {line_type}",
        ]
        return "\n".join(lines)

    except Exception as exc:
        err_msg = f"[!] Failed to parse phone number '{phone_number}': {exc}"
        return {"error": str(exc)} if raw else err_msg

"""KaraQargha CLI Entry Point.

Modular terminal OSINT framework supporting breach intelligence,
email enumeration, username recon, phone lookup, and IP geolocation.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

# Ensure package imports resolve when executed directly as a script
import os
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from karagargha.core import colors
from karagargha.core.report import generate_json_report, generate_txt_report, generate_html_report, save_report
from karagargha.core.spinner import Spinner
from karagargha.modules.breach import scan_breaches
from karagargha.modules.email import scan_email, scan_email_headers
from karagargha.modules.ip import scan_ip
from karagargha.modules.phone import scan_phone
from karagargha.modules.social import scan_social
from karagargha.modules.username import scan_username
from karagargha.modules.domain import scan_domain
from karagargha.modules.crypto import scan_crypto
from karagargha.modules.image import scan_image
from karagargha.modules.sanctions import scan_sanctions


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="karagargha",
        description="KaraQargha — Command-Line Open Source Intelligence (OSINT) Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  karagargha -e victim@example.com
  karagargha -u johndoe -o results.json
  karagargha -p +14155552671
  karagargha -i 8.8.8.8
  karagargha -a target@example.com --json
  karagargha -e test@mail.com -o report.txt
        """,
    )

    parser.add_argument(
        "-e",
        "--email",
        metavar="EMAIL",
        help="Email breach + account registration scan",
    )
    parser.add_argument(
        "-u",
        "--username",
        metavar="USERNAME",
        help="Username reconnaissance across social platforms",
    )
    parser.add_argument(
        "-p",
        "--phone",
        metavar="PHONE",
        help="Phone number lookup (validity, carrier, region, timezone)",
    )
    parser.add_argument(
        "-i",
        "--ip",
        metavar="IP",
        help="IP address geolocation and security proxy detection",
    )
    parser.add_argument(
        "-a",
        "--all",
        metavar="TARGET",
        dest="all_target",
        help="Run comprehensive email + username scan for one target",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Save report to file (.txt or .json auto-detected by extension)",
    )
    parser.add_argument("-d", "--domain", metavar="DOMAIN", help="Domain & DNS intelligence")
    parser.add_argument("--headers", metavar="FILE", help="Analyze raw email headers from file")
    parser.add_argument("-c", "--crypto", metavar="ADDRESS", help="Bitcoin address summary")
    parser.add_argument("--image", metavar="FILE", help="Image EXIF metadata")
    parser.add_argument("-s", "--sanctions", metavar="NAME", help="Screen a name/entity against OFAC SDN")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Force raw JSON output to stdout",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate an HTML report under the reports/ folder",
    )

    return parser


def run_scans(args: argparse.Namespace) -> int:
    """Execute target scans according to user arguments."""
    # Ensure Windows console uses UTF-8 without decoding crashes
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    is_json = bool(args.json)
    spinner_enabled = not is_json

    # Load .env if present
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass

    if not is_json:
        colors.init_colors()
        print(colors.get_banner())
        # First-run / usage notice
        notice_flag = os.path.join(os.path.expanduser("~"), ".karagargha_seen")
        if not os.path.exists(notice_flag):
            print(colors.warning("Notice: Use this tool only on your own data, your own assets, or with the owner's permission."))
            try:
                with open(notice_flag, "w") as f:
                    f.write("seen")
            except Exception:
                pass

    # Verify that at least one scan option was requested
    has_target = any([args.email, args.username, args.phone, args.ip, args.all_target, args.domain, args.headers, args.crypto, args.image, args.sanctions])
    if not has_target:
        if not is_json:
            print(colors.info("No scan target specified. Use -h or --help for instructions."))
            print(colors.info("Quick start: karagargha -e user@example.com or karagargha -u username"))
        else:
            print(json.dumps({"error": "No scan target specified."}, indent=2))
        return 1

    section_texts: Dict[str, str] = {}
    structured_results: Dict[str, Any] = {}
    primary_target_type = "unknown"
    primary_target_val = ""

    # 1. EMAIL SCAN (-e / --email)
    if args.email:
        target_email = args.email.strip()
        primary_target_type = "email"
        primary_target_val = target_email

        # HaveIBeenPwned Breaches
        with Spinner(f"[~] Scanning breaches for {target_email} ...", enabled=spinner_enabled):
            breach_text = str(scan_breaches(target_email, raw=False))
            breach_raw = scan_breaches(target_email, raw=True)
        section_texts["HaveIBeenPwned Breaches"] = breach_text
        structured_results["breaches"] = breach_raw

        # Holehe Email Registrations
        with Spinner(f"[~] Enumerating registered accounts for {target_email} ...", enabled=spinner_enabled):
            email_text = str(scan_email(target_email, raw=False))
            email_raw = scan_email(target_email, raw=True)
        section_texts["Email Registrations"] = email_text
        structured_results["email_registrations"] = email_raw

        # Social & Gravatar
        with Spinner(f"[~] Checking Gravatar & pastes for {target_email} ...", enabled=spinner_enabled):
            social_text = str(scan_social(target_email, raw=False))
            social_raw = scan_social(target_email, raw=True)
        section_texts["Social & Leaks"] = social_text
        structured_results["social"] = social_raw

    # 2. USERNAME SCAN (-u / --username)
    if args.username:
        target_user = args.username.strip()
        if primary_target_type == "unknown":
            primary_target_type = "username"
            primary_target_val = target_user

        with Spinner(f"[~] Scanning platforms for username '{target_user}' ...", enabled=spinner_enabled):
            user_text = str(scan_username(target_user, raw=False))
            user_raw = scan_username(target_user, raw=True)
        section_texts["Username Reconnaissance"] = user_text
        structured_results["username_profiles"] = user_raw

    # 3. PHONE SCAN (-p / --phone)
    if args.phone:
        target_phone = args.phone.strip()
        if primary_target_type == "unknown":
            primary_target_type = "phone"
            primary_target_val = target_phone

        with Spinner(f"[~] Querying phone metadata for {target_phone} ...", enabled=spinner_enabled):
            phone_text = str(scan_phone(target_phone, raw=False))
            phone_raw = scan_phone(target_phone, raw=True)
        section_texts["Phone Intelligence"] = phone_text
        structured_results["phone"] = phone_raw

    # 4. IP SCAN (-i / --ip)
    if args.ip:
        target_ip = args.ip.strip()
        if primary_target_type == "unknown":
            primary_target_type = "ip"
            primary_target_val = target_ip

        with Spinner(f"[~] Geolocating IP address {target_ip} ...", enabled=spinner_enabled):
            ip_text = str(scan_ip(target_ip, raw=False))
            ip_raw = scan_ip(target_ip, raw=True)
        section_texts["IP Geolocation"] = ip_text
        structured_results["ip"] = ip_raw

    # DOMAIN SCAN
    if args.domain:
        target = args.domain.strip()
        if primary_target_type == "unknown":
            primary_target_type = "domain"
            primary_target_val = target
        with Spinner(f"[~] Analysing domain {target} ...", enabled=spinner_enabled):
            d_text = str(scan_domain(target, raw=False))
            d_raw = scan_domain(target, raw=True)
        section_texts["Domain Intelligence"] = d_text
        structured_results["domain"] = d_raw

    # EMAIL HEADERS
    if args.headers:
        with Spinner(f"[~] Parsing email headers from {args.headers} ...", enabled=spinner_enabled):
            h_text = str(scan_email_headers(args.headers, raw=False))
            h_raw = scan_email_headers(args.headers, raw=True)
        section_texts["Email Header Analysis"] = h_text
        structured_results["email_headers"] = h_raw

    # CRYPTO
    if args.crypto:
        target = args.crypto.strip()
        if primary_target_type == "unknown":
            primary_target_type = "crypto"
            primary_target_val = target
        with Spinner(f"[~] Querying Bitcoin address {target} ...", enabled=spinner_enabled):
            c_text = str(scan_crypto(target, raw=False))
            c_raw = scan_crypto(target, raw=True)
        section_texts["Crypto Intelligence"] = c_text
        structured_results["crypto"] = c_raw

    # IMAGE
    if args.image:
        with Spinner(f"[~] Extracting EXIF from {args.image} ...", enabled=spinner_enabled):
            im_text = str(scan_image(args.image, raw=False))
            im_raw = scan_image(args.image, raw=True)
        section_texts["Image Metadata"] = im_text
        structured_results["image"] = im_raw

    # SANCTIONS
    if args.sanctions:
        target = args.sanctions.strip()
        if primary_target_type == "unknown":
            primary_target_type = "sanctions"
            primary_target_val = target
        with Spinner(f"[~] Screening '{target}' against OFAC SDN ...", enabled=spinner_enabled):
            sa_text = str(scan_sanctions(target, raw=False))
            sa_raw = scan_sanctions(target, raw=True)
        section_texts["Sanctions Screening"] = sa_text
        structured_results["sanctions"] = sa_raw

    # 5. ALL SCAN (-a / --all TARGET)
    if args.all_target:
        target_all = args.all_target.strip()
        primary_target_type = "all"
        primary_target_val = target_all

        # Determine if target is email or username
        is_email = "@" in target_all
        email_cand = target_all if is_email else f"{target_all}@gmail.com"
        user_cand = target_all.split("@")[0] if is_email else target_all

        # Breaches
        with Spinner(f"[~] Scanning breaches for {email_cand} ...", enabled=spinner_enabled):
            breach_text = str(scan_breaches(email_cand, raw=False))
            breach_raw = scan_breaches(email_cand, raw=True)
        section_texts["HaveIBeenPwned Breaches"] = breach_text
        structured_results["breaches"] = breach_raw

        # Holehe registrations
        with Spinner(f"[~] Enumerating registered accounts for {email_cand} ...", enabled=spinner_enabled):
            email_text = str(scan_email(email_cand, raw=False))
            email_raw = scan_email(email_cand, raw=True)
        section_texts["Email Registrations"] = email_text
        structured_results["email_registrations"] = email_raw

        # Social & Gravatar
        with Spinner(f"[~] Checking Gravatar & pastes for {email_cand} ...", enabled=spinner_enabled):
            social_text = str(scan_social(email_cand, raw=False))
            social_raw = scan_social(email_cand, raw=True)
        section_texts["Social & Leaks"] = social_text
        structured_results["social"] = social_raw

        # Username scan
        with Spinner(f"[~] Scanning platforms for username '{user_cand}' ...", enabled=spinner_enabled):
            user_text = str(scan_username(user_cand, raw=False))
            user_raw = scan_username(user_cand, raw=True)
        section_texts["Username Reconnaissance"] = user_text
        structured_results["username_profiles"] = user_raw

    # Construct report payloads
    json_report = generate_json_report(primary_target_type, primary_target_val, structured_results)
    txt_report = generate_txt_report(primary_target_type, primary_target_val, section_texts)

    # Output to stdout
    if is_json:
        print(json.dumps(json_report, indent=2, ensure_ascii=False))
    else:
        for title, content in section_texts.items():
            print(colors.header(title))
            print(content)
        print()

    # Save to file if -o / --output specified
    if args.output:
        save_msg = save_report(args.output, json_report, txt_report)
        if not is_json:
            print(save_msg)

    # HTML report under reports/
    if getattr(args, "html", False):
        os.makedirs("reports", exist_ok=True)
        import datetime as _dt
        fname = f"reports/report_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_content = generate_html_report(primary_target_type, primary_target_val, structured_results, section_texts)
        with open(fname, "w", encoding="utf-8") as f:
            f.write(html_content)
        if not is_json:
            print(colors.found(f"HTML report saved: {os.path.abspath(fname)}"))

    return 0


def interactive() -> int:
    """Interactive menu shown when no CLI arguments are supplied."""
    colors.init_colors()
    print(colors.get_banner())
    while True:
        print(colors.header("Interactive Menu"))
        print("  1. Email scan")
        print("  2. Username scan")
        print("  3. Phone lookup")
        print("  4. IP lookup")
        print("  5. Domain intelligence")
        print("  6. Email header analysis")
        print("  7. Crypto (BTC) summary")
        print("  8. Image EXIF metadata")
        print("  9. Sanctions screening")
        print(" 10. Comprehensive scan (-a)")
        print("  0. Exit")
        try:
            choice = input(colors.info("Select option: ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "0":
            return 0
        if choice not in {str(i) for i in range(1, 11)}:
            print(colors.warning("Invalid choice."))
            continue

        args = argparse.Namespace(
            email=None, username=None, phone=None, ip=None, all_target=None,
            domain=None, headers=None, crypto=None, image=None, sanctions=None,
            output=None, json=False, html=False,
        )
        if choice == "1":
            args.email = input("Email: ").strip()
        elif choice == "2":
            args.username = input("Username: ").strip()
        elif choice == "3":
            args.phone = input("Phone: ").strip()
        elif choice == "4":
            args.ip = input("IP: ").strip()
        elif choice == "5":
            args.domain = input("Domain: ").strip()
        elif choice == "6":
            args.headers = input("Headers file: ").strip()
        elif choice == "7":
            args.crypto = input("BTC address: ").strip()
        elif choice == "8":
            args.image = input("Image file: ").strip()
        elif choice == "9":
            args.sanctions = input("Name/Entity: ").strip()
        elif choice == "10":
            args.all_target = input("Target: ").strip()

        try:
            run_scans(args)
        except Exception as exc:
            print(colors.fail(f"Error: {exc}"))
        print()


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return interactive()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run_scans(args)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Scan interrupted by user.\n")
        return 130
    except Exception as exc:
        sys.stderr.write(f"\n[!] Unexpected error: {exc}\n")
        return 1


def cli_entry() -> None:
    """Console script wrapper."""
    sys.exit(main())


if __name__ == "__main__":
    cli_entry()

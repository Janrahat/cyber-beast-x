#!/usr/bin/env python3
"""CYBER BEAST X — basic, permission-based security and OSINT utilities."""

import ipaddress
import json
import platform
import socket
import sys
from datetime import datetime
from urllib.parse import urlparse

import phonenumbers
import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

console = Console()
REPORT_FILE = "cyber_beast_reports.json"
TIMEOUT = 10


def banner():
    console.clear()
    console.print(Panel.fit(
        "[bold bright_green]CYBER BEAST X[/bold bright_green]\n"
        "[bright_cyan]Basic Security & OSINT Toolkit[/bright_cyan]\n"
        "[yellow]Termux | Kali Linux[/yellow]",
        border_style="bright_magenta",
    ))


def save_report(module, result):
    record = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "module": module,
        "result": result,
    }
    try:
        with open(REPORT_FILE, "r", encoding="utf-8") as file:
            reports = json.load(file)
        if not isinstance(reports, list):
            reports = []
    except (FileNotFoundError, json.JSONDecodeError):
        reports = []
    reports.append(record)
    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(reports, file, indent=2, ensure_ascii=False)
    console.print(f"[green]Saved report to {REPORT_FILE}[/green]")


def show_result(title, data):
    table = Table(title=title, border_style="bright_cyan")
    table.add_column("Field", style="bright_green")
    table.add_column("Value", style="white")
    for key, value in data.items():
        table.add_row(str(key), str(value))
    console.print(table)


def ip_lookup():
    raw_ip = Prompt.ask("Public IP address")
    try:
        ip = ipaddress.ip_address(raw_ip.strip())
        if not ip.is_global:
            console.print("[yellow]Enter a globally routable public IP address.[/yellow]")
            return
        response = requests.get(f"https://ipwho.is/{ip}", timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        if not data.get("success", False):
            console.print("[red]Lookup service could not return details.[/red]")
            return
        connection = data.get("connection") or {}
        result = {
            "ip": data.get("ip"),
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "isp": connection.get("isp"),
            "organization": connection.get("org"),
            "note": "Geolocation is approximate; it does not reveal a person's exact address.",
        }
        show_result("PUBLIC IP INFORMATION", result)
        save_report("IP Lookup", result)
    except (ValueError, requests.RequestException) as exc:
        console.print(f"[red]Lookup error: {exc}[/red]")


def phone_lookup():
    raw_number = Prompt.ask("Phone number (prefer international format, e.g. +14155552671)")
    region = Prompt.ask("Region if number has no country code (e.g. US, GB, PK)", default="").strip().upper()
    try:
        parsed = phonenumbers.parse(raw_number, region or None)
        result = {
            "international_format": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            ),
            "country_calling_code": parsed.country_code,
            "possible_number": phonenumbers.is_possible_number(parsed),
            "valid_numbering_plan": phonenumbers.is_valid_number(parsed),
            "number_type": str(phonenumbers.number_type(parsed)),
            "limitation": "Does not identify the subscriber or reveal private location.",
        }
        show_result("PHONE NUMBER FORMAT CHECK", result)
        save_report("Phone Number Analysis", result)
    except phonenumbers.NumberParseException as exc:
        console.print(f"[red]Could not parse number: {exc}[/red]")


def dns_lookup():
    host = Prompt.ask("Domain name (e.g. example.com)").strip()
    if "://" in host:
        host = urlparse(host).hostname or ""
    host = host.rstrip(".")
    if not host or "/" in host or " " in host:
        console.print("[red]Please enter a valid domain name.[/red]")
        return
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        result = {"domain": host, "resolved_addresses": addresses}
        show_result("DNS LOOKUP", result)
        save_report("DNS Lookup", result)
    except socket.gaierror:
        console.print("[red]Domain could not be resolved.[/red]")


def website_check():
    raw = Prompt.ask("URL for a site you own or are authorized to test")
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        console.print("[red]Invalid URL.[/red]")
        return
    try:
        response = requests.get(
            candidate,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "CyberBeastX/1.0"},
        )
        headers = response.headers
        result = {
            "requested_url": candidate,
            "final_url": response.url,
            "status_code": response.status_code,
            "https_used_after_redirects": response.url.startswith("https://"),
            "server_header": headers.get("Server", "Not disclosed"),
            "content_type": headers.get("Content-Type", "Unknown"),
            "strict_transport_security": headers.get("Strict-Transport-Security", "Not present"),
            "content_security_policy": headers.get("Content-Security-Policy", "Not present"),
            "note": "Header checks are a basic indicator, not a full security audit.",
        }
        show_result("BASIC WEBSITE CHECK", result)
        save_report("Website Check", result)
    except requests.RequestException as exc:
        console.print(f"[red]Request failed: {exc}[/red]")


def system_info():
    result = {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "hostname": socket.gethostname(),
    }
    show_result("SYSTEM INFORMATION", result)
    save_report("System Information", result)


def view_reports():
    try:
        with open(REPORT_FILE, "r", encoding="utf-8") as file:
            reports = json.load(file)
        console.print_json(data=reports)
    except (FileNotFoundError, json.JSONDecodeError):
        console.print("[yellow]No saved reports yet.[/yellow]")


def main():
    actions = {
        "1": ("Public IP Information", ip_lookup),
        "2": ("Phone Number Format Analysis", phone_lookup),
        "3": ("DNS Lookup", dns_lookup),
        "4": ("Basic Website Check", website_check),
        "5": ("System Information", system_info),
        "6": ("View Saved Reports", view_reports),
    }
    while True:
        banner()
        table = Table(title="MAIN MENU", border_style="bright_blue")
        table.add_column("Option", style="bright_yellow")
        table.add_column("Module", style="bright_white")
        for key, (label, _) in actions.items():
            table.add_row(key, label)
        table.add_row("0", "Exit")
        console.print(table)
        choice = Prompt.ask("Choose", choices=[*actions.keys(), "0"], default="0")
        if choice == "0":
            console.print("[bright_green]Stay safe. Goodbye![/bright_green]")
            break
        actions[choice][1]()
        Prompt.ask("Press Enter to return to the menu", default="")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Exited.[/yellow]")

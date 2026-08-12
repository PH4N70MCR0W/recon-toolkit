#!/usr/bin/env python3
"""Simple OSCP-style enumeration wrapper.

Runs an initial nmap sweep, parses the open ports from XML output, and
fires per-service follow-up enumeration. Extend the HANDLERS dict below.
"""

import subprocess
import sys
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path


def run(cmd, outfile=None):
    """Run a command; optionally redirect stdout+stderr to a file."""
    if outfile:
        with open(outfile, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
    else:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def have(tool):
    """True if a tool is on PATH."""
    return shutil.which(tool) is not None


def discover_ports(target, outdir):
    """Full TCP sweep, return list of open port numbers."""
    print("[*] Discovering open TCP ports...")
    xml = outdir / "nmap" / "allports.xml"
    run(["nmap", "-p-", "--min-rate", "2000", "-T4", "-oX", str(xml), target])
    ports = []
    if xml.exists():
        root = ET.parse(xml).getroot()
        for port in root.iter("port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                ports.append(port.get("portid"))
    return ports


def scan_services(target, ports, outdir):
    """Service/version + default-script scan. Return {port: service}."""
    print("[*] Running service + default-script scan...")
    xml = outdir / "nmap" / "services.xml"
    run([
        "nmap", "-sC", "-sV", "-p", ",".join(ports),
        "-oN", str(outdir / "nmap" / "services.nmap"),
        "-oX", str(xml), target,
    ])
    services = {}
    if xml.exists():
        root = ET.parse(xml).getroot()
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            name = svc.get("name") if svc is not None else "unknown"
            services[port.get("portid")] = name
    return services


# --- per-service follow-up handlers --------------------------------
def handle_http(target, port, outdir, scheme="http"):
    if have("whatweb"):
        run(["whatweb", f"{scheme}://{target}:{port}"],
            outdir / "web" / f"whatweb_{port}.txt")
    if scheme == "http" and have("feroxbuster"):
        run(["feroxbuster", "-u", f"http://{target}:{port}", "-q",
             "-o", str(outdir / "web" / f"ferox_{port}.txt")])


def handle_smb(target, port, outdir):
    if have("enum4linux-ng"):
        run(["enum4linux-ng", "-A", target],
            outdir / "smb" / f"enum4linux_{port}.txt")
    if have("smbclient"):
        run(["smbclient", "-N", "-L", f"//{target}"],
            outdir / "smb" / f"shares_{port}.txt")


def follow_up(target, services, outdir):
    for port, service in services.items():
        print(f"[*] Follow-up for {service} ({port})")
        if service == "http":
            handle_http(target, port, outdir, "http")
        elif service == "https" or service.startswith("ssl"):
            handle_http(target, port, outdir, "https")
        elif service in ("microsoft-ds", "netbios-ssn"):
            handle_smb(target, port, outdir)
        else:
            note = outdir / "misc" / f"todo_{port}.txt"
            note.write_text(
                f"No handler for '{service}' on {port} — enumerate manually.\n")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target-ip>")
        sys.exit(1)

    target = sys.argv[1]
    outdir = Path(f"enum_{target}")
    for sub in ("nmap", "web", "smb", "misc"):
        (outdir / sub).mkdir(parents=True, exist_ok=True)
    print(f"[*] Target: {target}   Output: {outdir}")

    ports = discover_ports(target, outdir)
    if not ports:
        print("[!] No open ports found.")
        sys.exit(0)
    print(f"[+] Open ports: {','.join(ports)}")

    services = scan_services(target, ports, outdir)
    follow_up(target, services, outdir)
    print(f"[+] Done. Review {outdir}/")


if __name__ == "__main__":
    main()

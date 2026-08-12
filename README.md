# recon-toolkit

An OSCP-style enumeration wrapper. It runs an initial full-port `nmap`
sweep, parses the open ports, and fires off per-service follow-up
enumeration so you spend less time on boilerplate and more time on the
interesting findings.

Built as a learning project while preparing for the OSCP — the goal is
a tool where I can explain every line, not a black box.

## Usage

Two implementations are provided — same workflow, pick whichever you prefer:

```bash
./enum.sh <target-ip>     # Bash version, minimal dependencies
./enum.py <target-ip>     # Python version, XML parsing, easier to extend
```

If the scripts aren't executable yet, run them directly instead:

```bash
bash enum.sh <target-ip>
python3 enum.py <target-ip>
```

Results are written to `enum_<target>/`, organised per category:
...

enum_10.10.10.10/
├── nmap/ # raw scan output
├── web/ # whatweb + feroxbuster per HTTP(S) port
├── smb/ # enum4linux-ng + share listing
└── misc/ # notes and TODOs
...


## What it does

1. **Port discovery** — fast full TCP sweep (`nmap -p-`)
2. **Service detection** — version + default-script scan on open ports
3. **Follow-up** — per-service enumeration (HTTP, SMB, FTP, SSH, …),
   with a catch-all that flags anything it doesn't yet handle

## Requirements

`nmap`, and optionally `whatweb`, `feroxbuster`, `enum4linux-ng`,
`smbclient`. Missing tools are skipped rather than fatal.

## Disclaimer

For use only against systems you are explicitly authorised to test
(lab environments, CTF platforms, or engagements with written scope).

## License

MIT — see [LICENSE](LICENSE).

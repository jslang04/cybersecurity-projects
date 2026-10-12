# Security Monitoring & Threat Detection Home Lab

A three-VM lab built to simulate, capture, and investigate a simple SSH brute-force
intrusion — from initial recon through a simulated persistence step — using the
same categories of tools (Nmap, Wireshark/tshark, Splunk) found in entry-level
SOC/security-monitoring roles.

## Architecture

Three VirtualBox VMs on a shared Host-only network (`192.168.56.0/24`), each also
retaining a NAT adapter for internet/package access:

| VM | Role | Host-only IP | Notes |
|---|---|---|---|
| `ubuntu-target` | Target / victim host | 192.168.56.101 | Ubuntu Server, OpenSSH enabled |
| `kali-attacker` | Attacker | 192.168.56.102 | Kali Linux, pre-built VirtualBox image |
| `ubuntu-monitor` | Defender / monitoring host | 192.168.56.103 | Ubuntu Server, promiscuous mode enabled on the host-only adapter, `tshark` installed |

The Monitor VM's adapter is set to **Promiscuous Mode: Allow All**, replicating how a
SPAN/mirror port lets a monitoring host see traffic between two other hosts on a
switched network, rather than only its own.

## What was done

**Reconnaissance (Nmap)**
A default scan followed by a version/OS-detection scan (`nmap -sV -A`) was run from
Kali against the target, confirming port 22/tcp (SSH) open and identifying the exact
OpenSSH version string. Banner disclosure of the specific SSH version is itself a
minor finding — it lets an attacker narrow down known CVEs for that build (CWE-200,
information exposure).

**Simulated attack (SSH brute force + post-access activity)**
From Kali, multiple SSH sessions were run against the target using incorrect
passwords, each session terminating after 3 failed attempts (SSH's `MaxAuthTries`
protection), followed by one successful login using the correct credentials. After
gaining access, basic reconnaissance commands (`whoami`, `id`) were run, and a new
user account (`backdoor_user`) was created to simulate an attacker establishing
persistence.

**Log evidence (Ubuntu auth.log)**
The target's `/var/log/auth.log` was reviewed and filtered to isolate SSH-relevant
entries. The log clearly distinguishes `Failed password` vs `Accepted password`
events, each tagged with source IP and source port, and shows the `[preauth]`
disconnects triggered by `MaxAuthTries`. Nine failed authentication attempts across
three sessions preceded the single successful login — a pattern (volume + timing)
that is the actual basis for automated brute-force detection in a real SIEM.

**Packet capture (tshark, from the Monitor VM)**
A full packet capture (`attack_chain.pcap`) was taken from the Monitor VM — not the
attacker or the target — filtered to `tcp port 22`, covering the failed logins,
successful login, and post-access commands. The capture shows the TCP handshake and
SSH protocol/version negotiation in the clear, but all traffic after the SSH session
is established (including the `useradd` command itself) appears as encrypted packets.
This is worth stating explicitly: a network-only observer can see *that* an SSH
session occurred and its rough shape (timing, packet sizes, session duration), but
not *what* was typed — the auth log on the target remains the authoritative source
for the actual commands and outcomes.

**SIEM (Splunk)**
Splunk Enterprise (free tier) was installed on the Monitor VM with the intent of
forwarding the target's `auth.log` via a Universal Forwarder and building a
correlation search/alert for repeated failed SSH logins (mapping to MITRE ATT&CK
T1110.001). Installation and initial configuration were completed, but a disk-space
exhaustion issue during setup (traced to VM disk/LVM sizing, not Splunk itself)
prevented a clean admin account from being seeded before time ran out on this pass
of the lab. Splunk's role in the architecture, its data-ingestion model, and SPL
(Search Processing Language) were reviewed via Splunk's own documentation and
training materials in place of a completed local deployment.

## MITRE ATT&CK Mapping

| Activity | Technique | ID |
|---|---|---|
| Repeated failed SSH login attempts | Brute Force: Password Guessing | T1110.001 |
| `whoami` / `id` after gaining access | System Owner/User Discovery | T1033 |
| Creation of `backdoor_user` | Create Account | T1136 |

## Artifacts in this repo

- `scan_results.txt` — Nmap version/OS-detection scan output
- `ssh_bruteforce_log.txt` — filtered `auth.log` excerpt covering the brute-force + successful login sequence
- `attack_chain.pcap` — full packet capture of the attack sequence, captured from the Monitor VM

## What this demonstrates

- Building and networking a multi-VM lab environment from scratch (VirtualBox, host-only
  networking, promiscuous mode / SPAN-port equivalence)
- Reconnaissance and service enumeration with Nmap
- Reading and interpreting Linux authentication logs to distinguish normal vs.
  suspicious activity
- Packet capture and the practical difference between what's visible at the network
  layer vs. the log layer for an encrypted protocol
- Mapping observed technical activity to MITRE ATT&CK techniques — translating raw
  technical findings into a structured, documented security narrative

## Possible extensions

- Complete the Splunk forwarder configuration and build a correlation search/alert
  for the T1110.001 pattern (≥5 failed logins from one source within a short window)
- Add a second attack scenario (e.g. a web service misconfiguration) to broaden the
  MITRE coverage
- Compare detection coverage/gaps against a specific compliance framework (e.g. which
  NIST 800-53 or CIS controls this kind of monitoring would satisfy) — a natural
  extension given the security-monitoring-to-GRC connection

# security-research

Independent security research. Vulnerability disclosure work from bug bounty
programs, and malware analysis going past what the press release says.

## Contents

| Path | What it is |
|---|---|
| `8x8/8x8_reports.md` | three HackerOne reports against 8x8's Jitsi/JaaS telephony infrastructure — unauthenticated phone authorization, and two issues fixed upstream in Jitsi v9673 and v10532 |
| `nairaprop/` | full pentest of a Nigerian property platform — 5 exploit chains, 47 findings, in Markdown, PDF and DOCX |
| `wannacry-research/` | WannaCry analysis focused on what the public account left out: the kill switch as sandbox evasion, the three switch domains, the 59-day patch gap, and the unrecovered per-victim keys |

## Disclosure status

**8x8** — submitted through the HackerOne bug bounty program, in scope. Two of
the three were fixed upstream in Jitsi and carry the fixing version in the
report.

**NairaProp** — **not disclosed, and not authorized.** See below.

**WannaCry** — research on public reporting of a 2017 attack. No disclosure
involved.

## Read this before you look at nairaprop/

The NairaProp report documents unpatched, currently-exploitable vulnerabilities
against a **live financial platform**, including a KYC identity-theft chain and
admin-token theft via stored XSS. The report also contains the testing account
email, live infrastructure hostnames, and production database schema detail.

It is public on this profile right now. Before you share the profile, decide
which of these you want:

- **Gotten a fix in place and disclosed properly** — remove the exploit chains
  and the identifying infrastructure detail from the public copy, or make the
  repo private and share excerpts.
- **Reported it and it is still open** — make the repo private. A public repo
  carrying a working chain against a live fintech is publishing an exploit,
  regardless of intent.
- **It was never actually reported** — that is the serious case, and it needs
  handling before publication, not after.

I have not changed this repo because I do not know the current state of the
report, and publishing or unpublishing that decision belongs to you.

## Honest limitations

- **Writeups, not tooling.** No scripts, no detection rules, no reproducible
  harness. The tooling lives in
  [pcap-triage](https://github.com/shadow-ciper/pcap-triage) and
  [threat-hunter-toolkit](https://github.com/shadow-ciper/threat-hunter-toolkit).
- **Single-file commits.** Everything landed as `Add files via upload`, so there
  is no history showing how the analysis developed. For a research portfolio the
  process is often more interesting than the conclusion.

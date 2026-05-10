# WannaCry Ransomware — The Untold Story

> **Research Type:** Malware Analysis / Threat Actor Profiling  
> **Date of Attack:** May 12, 2017  
> **Researcher:** ShadowCiper  
> **Status:** Published  

---

## Table of Contents

1. [Overview](#overview)
2. [What Everyone Already Knows](#what-everyone-already-knows)
3. [What Most People Don't Know](#what-most-people-dont-know)
   - [The Kill Switch Was a Sandbox Detector, Not a Backdoor](#1-the-kill-switch-was-a-sandbox-detector-not-a-backdoor)
   - [There Were Three Kill Switches, Not One](#2-there-were-three-kill-switches-not-one)
   - [Victims Could Recover Files Without Paying](#3-victims-could-recover-files-without-paying)
   - [The Ransom Was Comically Small and Mostly Uncollected](#4-the-ransom-was-comically-small-and-mostly-uncollected)
   - [The NSA Sat on the Vulnerability for Years](#5-the-nsa-sat-on-the-vulnerability-for-years)
   - [The Patch Was Available 59 Days Before the Attack](#6-the-patch-was-available-59-days-before-the-attack)
   - [EternalBlue Only Exploited a 30-Year-Old Protocol](#7-eternalblue-only-exploited-a-30-year-old-protocol)
   - [WannaCry Is Still Active Today](#8-wannacry-is-still-active-today)
   - [The Financial Motive Never Added Up](#9-the-financial-motive-never-added-up)
   - [The Payload Bundled a Copy of the Tor Browser](#10-the-payload-bundled-a-copy-of-the-tor-browser)
4. [Attack Chain](#attack-chain)
5. [Key Takeaways](#key-takeaways)
6. [References](#references)

---

## Overview

On **May 12, 2017 at approximately 07:44 UTC**, a cybersecurity researcher named **Marcus Hutchins** detected a fast-spreading cryptoworm tearing through networks across the globe. Within 24 hours, it had hit over **200,000 machines across 150+ countries** — crippling hospitals, banks, railways, and telecoms.

The world called it WannaCry. The security community called it a wake-up call that was ignored.

This research focuses on what the mainstream coverage missed.

---

## What Everyone Already Knows

- WannaCry was a ransomware worm that encrypted files and demanded Bitcoin payment
- It spread using **EternalBlue**, an NSA exploit leaked by the Shadow Brokers
- Marcus Hutchins accidentally stopped it by registering a hardcoded domain (the "kill switch")
- Major victims included the UK's NHS, FedEx, Deutsche Bahn, and Telefonica
- North Korea's Lazarus Group (APT38) was officially attributed as the threat actor

---

## What Most People Don't Know

### 1. The Kill Switch Was a Sandbox Detector, Not a Backdoor

Most people believe Hutchins found a developer mistake — a forgotten off switch. The reality is more calculated.

Security researchers determined that the kill switch domain was deliberately hardcoded as an **anti-analysis mechanism**. The logic: a real internet connection returns no response from a nonexistent domain. A security sandbox, however, mimics real internet behaviour and may return a fake "live" response. If WannaCry received a response from the domain, it assumed it was being analyzed inside a sandbox — and shut itself down to avoid detection.

Hutchins registering the domain was never the intended behavior. It was an accidental fix to an intentional evasion technique.

---

### 2. There Were Three Kill Switches, Not One

The narrative locked onto Hutchins as the sole hero. What was underreported: **two additional kill switches** were discovered and activated after the first, further crippling WannaCry's spread. The full neutralization was a collective effort, not a single moment.

---

### 3. Victims Could Recover Files Without Paying

This is arguably the most underreported fact of the entire incident.

WannaCry's encryption implementation had a critical flaw: **the prime numbers used to generate private encryption keys were not properly cleared from system memory** after use. If the infected machine had not been rebooted and the WannaCry process was still running, those keys could potentially be extracted from RAM.

A French researcher exploited this to build **WannaKey**, a tool that automated key recovery on Windows XP systems. This was later iterated into **Wanakiwi**, which extended support to Windows 7 and Windows Server 2008 R2.

Most victims were never told this was possible.

---

### 4. The Ransom Was Comically Small — and Mostly Uncollected

WannaCry infected over 200,000 machines. The total ransom collected across the entire attack? Estimated at between **$150,000 and $386,900**.

The reason: WannaCry had no mechanism for the attackers to track who had paid. There was no automated decryption system tied to payment confirmation. Victims who paid had no reliable way to get their files back — and the attackers had no way to know who to decrypt. The payment model was fundamentally broken from day one.

---

### 5. The NSA Sat on the Vulnerability for Years

EternalBlue was not a fresh discovery. The NSA had possessed this exploit for **years** before it was stolen. They used it as an offensive tool while hundreds of thousands of Windows systems worldwide remained unknowingly exposed.

The Shadow Brokers stole it from the NSA-linked Equation Group and published it publicly in April 2017 — one month before WannaCry. Microsoft only learned of the vulnerability because the leak forced disclosure, not because the NSA reported it responsibly.

---

### 6. The Patch Was Available 59 Days Before the Attack

Microsoft released Security Bulletin **MS17-010** on **March 14, 2017** — explicitly flagged as **critical**. It directly patched the SMB vulnerability EternalBlue exploited.

WannaCry launched May 12, 2017. Every single infection was a patching failure, not a zero-day attack.

---

### 7. EternalBlue Only Exploited a 30-Year-Old Protocol

EternalBlue specifically targeted **SMBv1 (Server Message Block version 1)** — a file-sharing protocol dating back to the 1980s. By 2017, SMBv2 and SMBv3 had long superseded it. Organizations running SMBv1 in production environments in 2017 were operating on legacy infrastructure that had no business being internet-connected.

---

### 8. WannaCry Is Still Active Today

WannaCry was never eradicated. The kill switches stopped its worm propagation but did not remove existing infections or prevent reuse.

A surge of WannaCry activity was recorded in early 2020. By 2021, Check Point Research reported the number of organizations affected by WannaCry had grown by **53% year-over-year**. Unpatched Windows systems remain the fuel. The fire never went out — it just slowed down.

---

### 9. The Financial Motive Never Added Up

Given the scale of the attack versus the amount collected, most analysts now believe **the primary objective was disruption, not profit**. WannaCry represented one of the first confirmed cases of ransomware being deployed as a **state-sponsored weapon** — designed to cause damage to economies and critical infrastructure rather than generate meaningful revenue.

The US and UK governments attributed the attack to North Korea's Lazarus Group (APT38) in December 2017. The Lazarus Group had previously been linked to the 2014 Sony Pictures hack, the 2016 Bangladesh Central Bank heist, and attacks on Polish banks in early 2017.

---

### 10. The Payload Bundled a Copy of the Tor Browser

Inside WannaCry's encrypted ZIP payload, alongside configuration files and encryption keys, was a **bundled copy of the Tor browser**. This was included to route communications with the attacker's command-and-control infrastructure through the Tor anonymity network — making attribution and tracking significantly harder.

---

## Attack Chain

```
Shadow Brokers leak EternalBlue (April 2017)
        ↓
WannaCry dropper deployed on initial target machines
        ↓
DoublePulsar backdoor installed via EternalBlue (SMBv1 exploit)
        ↓
Kill switch domain queried → no response = not a sandbox → execution continues
        ↓
Files encrypted by Wana Decrypt0r 2.0 component
        ↓
Worm scans internet + local network for other unpatched SMBv1 hosts
        ↓
Ransom note displayed — $300 BTC (escalates to $600 after 3 days)
        ↓
Hutchins registers kill switch domain → worm propagation halted
        ↓
Two additional kill switches discovered and activated
```

---

## Key Takeaways

| Finding | Implication |
|--------|-------------|
| Kill switch was anti-sandbox logic | Malware evasion is baked in at design level — not an afterthought |
| Encryption keys leaked from RAM | Implementation flaws can undermine even strong cryptographic choices |
| $150K–$386K collected from 200K+ infections | Disruption, not profit, was the real goal |
| Patch existed 59 days prior | Most breaches are patch failures, not zero-days |
| SMBv1 exploitation | Legacy protocol debt is a first-class attack surface |
| Still active in 2021+ | Ransomware is never truly over — only dormant |

---

## References

- Wikipedia — WannaCry Ransomware Attack
- Cloudflare Learning — What Was the WannaCry Ransomware Attack?
- IBM X-Force — WannaCry: How the Widespread Ransomware Changed Cybersecurity
- CyberPeace Institute — WannaCry Is Not History
- CSO Online — WannaCry Explained: A Perfect Ransomware Storm
- Kaspersky Resource Center — WannaCry: All You Need to Know
- Fortinet Cybersecurity Glossary — WannaCry Ransomware Attack
- Acronis Blog — The NHS Cyber Attack
- Microsoft Security Bulletin MS17-010

---

*Research by ShadowCiper — part of the [security-research](https://github.com/ShadowCiper/security-research) repository.*

# Red-Team / PT Projects

This page is the quick map for the offensive-security side of the repo.

The tools here are meant for labs, CTFs, and authorized assessments. A lot of them intentionally work on **saved/local data** so I can practice the workflow without turning every project into another scanner.

## A simple workflow

### 1. Confirm scope

Use [Scope Guard](./scope-guard/) before testing a target list.

It can check IPs, CIDR networks, hostnames, domains, URLs, and explicit exclusions.

### 2. Run authorized recon

The repo's [Network Scanner](./network-scanner/) can handle basic host/subnet TCP checks.

For deeper lab work I can use Nmap separately and save XML.

### 3. Parse scan results

[Nmap Result Explorer](./nmap-result-explorer/) reads saved XML and turns it into cleaner host/service data or Markdown notes.

### 4. Map the web app

[Web Endpoint Inventory](./web-endpoint-inventory/) reads browser/Burp/ZAP HAR data or a URL list and builds a deduplicated endpoint/parameter inventory.

### 5. Use local helper utilities

[CTF Toolbox](./ctf-toolbox/) handles common encoding/decoding and format-identification tasks.

[Wordlist Lab](./wordlist-lab/) cleans and transforms user-provided wordlists without performing logins or cracking.

### 6. Keep evidence organized

[Evidence Organizer](./evidence-organizer/) copies evidence into a case folder, hashes every file, verifies it later, and builds an index.

### 7. Track findings

Use [Pentest Workbench](./pentest-workbench/) for findings, status tracking, tool history, and reports.

## What I am intentionally not putting here

This repo is not meant to contain malware, credential-stealing tools, phishing kits, persistence, stealth/evasion tooling, destructive payloads, or anything meant for unauthorized access.

The goal is useful PT workflow and portfolio projects that I can safely run in my own labs.

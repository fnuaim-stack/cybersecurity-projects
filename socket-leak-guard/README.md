# Socket Leak Guard

A Windows-first (also Linux-compatible) utility for finding processes that are consuming unusually large numbers of network sockets, watching for socket-count growth over time, identifying the owning process, and safely releasing sockets by stopping a selected non-critical process.

## What it does

- Ranks processes by total TCP/UDP socket count.
- Shows PID, process name, socket states, process start time, runtime, executable path, user, CPU and memory data.
- Highlights `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, and especially `CLOSE_WAIT` counts.
- Samples socket counts over time and flags medium/high growth trends that can indicate a leak.
- On Windows, `inspect` checks the executable's Authenticode signature and signer when available.
- Gives a conservative recommendation such as:
  - `keep / update OS`
  - `update / review`
  - `review / uninstall if unwanted`
- Refuses to terminate known critical OS processes.
- Uses dry-run behavior by default for remediation.
- Supports JSON output for automation.

## Install

```powershell
cd socket-leak-guard
python -m pip install -r requirements.txt
```

For the most complete Windows results, open PowerShell or Windows Terminal **as Administrator**.

## 1. Show the processes using the most sockets

```powershell
python socket_leak_guard.py top
```

Show more:

```powershell
python socket_leak_guard.py top --limit 30
```

Machine-readable output:

```powershell
python socket_leak_guard.py top --json
```

## 2. Watch for a socket leak

By default this takes 8 samples, 2 seconds apart:

```powershell
python socket_leak_guard.py watch
```

A longer observation window:

```powershell
python socket_leak_guard.py watch --samples 20 --interval 5
```

The detector looks for both absolute socket growth and percentage growth. It is a trend detector, not proof by itself that the application has a programming bug.

## 3. Inspect a suspicious PID

```powershell
python socket_leak_guard.py inspect 3508
```

Also list its network endpoints:

```powershell
python socket_leak_guard.py inspect 3508 --connections
```

This reports:

- process name and PID
- executable path
- user
- process start time and current runtime
- socket count and TCP state counts
- Windows signature status and signer when available
- importance level
- recommended action
- reason for the recommendation

The recommendation is intentionally conservative. It does not claim that an unknown program is malware and it never deletes an executable automatically.

## 4. Release sockets

An operating system owns the underlying socket resources for a process. There is no safe general-purpose way to forcibly close arbitrary individual sockets inside another application without risking corruption or undefined application behavior.

Socket Leak Guard therefore releases them by stopping the selected process, allowing the OS to reclaim all of that process's sockets.

Dry run:

```powershell
python socket_leak_guard.py release 3508
```

Gracefully terminate:

```powershell
python socket_leak_guard.py release 3508 --yes
```

If the application refuses to exit, you can explicitly allow a forced kill after the timeout:

```powershell
python socket_leak_guard.py release 3508 --yes --force
```

`--force` should only be used when you understand what the process is and have saved any work it controls.

## Safety controls

The tool refuses to terminate protected processes such as System, PID 0/1/4, LSASS, CSRSS, WININIT, SERVICES, WINLOGON, systemd/init, and itself.

It also does **not** automatically delete software. If an application is unwanted, uninstall it through Windows Settings, `winget uninstall`, the vendor uninstaller, or your Linux package manager instead of deleting its executable manually.

## Reading the results

A very high socket count is not automatically a leak. Browsers, proxies, game launchers, security tools, servers, and P2P applications can legitimately hold many connections.

Signals worth investigating include:

- socket count steadily grows and does not return toward baseline
- large or continually growing `CLOSE_WAIT` count
- the process has been running for a long time while socket count keeps rising
- stopping/restarting the process immediately restores network behavior
- the process is a non-essential utility that should not need that many network connections

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Scope

This is a local troubleshooting and defensive system-observability project. It reads local process/network metadata and only terminates a process when you explicitly request it.

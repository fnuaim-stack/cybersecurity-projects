# Socket Leak Guard

Shows which processes are using the most network sockets.

It can watch socket counts over time, inspect a process, and stop a selected non-system process so the OS releases its sockets.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python socket_leak_guard.py top
```

For full Windows process information, run the terminal as Administrator.

It is also in Pentest Workbench.

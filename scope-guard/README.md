# Scope Guard

A small safety/workflow tool for penetration tests and labs.

Before I run other tools, I can pass the target list through this script and make sure every host, IP, subnet, or URL is actually inside the scope I wrote down.

## Why I made it

It is easy to copy the wrong target into a command during a lab or assessment. This gives me one simple scope file that other tools can use as a gate.

## Scope file

Example:

```json
{
  "networks": ["192.168.56.0/24", "10.10.10.0/24"],
  "hosts": ["lab-app.local"],
  "domains": ["example.test"],
  "exclude_networks": ["192.168.56.240/28"],
  "exclude_hosts": ["do-not-test.example.test"]
}
```

Subdomains of an allowed domain are allowed too.

## Check targets

```bash
python scope_guard.py --scope sample_scope.json \
  --target 192.168.56.10 \
  --target https://app.example.test
```

Check a file:

```bash
python scope_guard.py --scope sample_scope.json --targets-file targets.txt
```

Write only allowed targets:

```bash
python scope_guard.py --scope sample_scope.json \
  --targets-file targets.txt \
  --allowed-output allowed.txt
```

Optional DNS resolution:

```bash
python scope_guard.py --scope sample_scope.json --target app.example.test --resolve
```

This does not scan anything. It only validates scope.

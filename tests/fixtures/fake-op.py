#!/usr/bin/env python3
"""A fake 1Password CLI for tests: just enough of `op` for op-secretd.

State lives in $FAKE_OP_DB (items/*.json, calls.log). Creating the file
$FAKE_OP_DB/FAIL makes every call fail like a dismissed approval prompt, and
$FAKE_OP_DB/SLOW (seconds) delays every call like a pending approval.
"""
import atexit
import json
import os
import sys

db = os.environ["FAKE_OP_DB"]
items_dir = os.path.join(db, "items")
os.makedirs(items_dir, exist_ok=True)
args = sys.argv[1:]

with open(os.path.join(db, "calls.log"), "a") as log:
    log.write(" ".join(args) + "\n")


def fail(message):
    sys.stderr.write("[ERROR] 2026/10/05 00:00:00 " + message + "\n")
    sys.exit(1)


if os.path.exists(os.path.join(db, "FAIL")):
    fail("authorization prompt dismissed")

# Record how many fake ops run at the same time (tests read concurrency.log).
running_dir = os.path.join(db, "running")
os.makedirs(running_dir, exist_ok=True)
marker = os.path.join(running_dir, str(os.getpid()))
open(marker, "w").close()
atexit.register(lambda: os.path.exists(marker) and os.remove(marker))
with open(os.path.join(db, "concurrency.log"), "a") as handle:
    handle.write("%d\n" % len(os.listdir(running_dir)))

slow = os.path.join(db, "SLOW")
if os.path.exists(slow):
    import time
    time.sleep(float(open(slow).read() or "1"))

# `FAIL_LIST` makes only `item list` fail, to test paths that must not depend on it.
if args[:2] == ["item", "list"] and os.path.exists(os.path.join(db, "FAIL_LIST")):
    fail("fake: listing is unavailable")

# Drop global flags; remember the interesting ones.
flags = {}
positional = []
i = 0
while i < len(args):
    arg = args[i]
    if arg in ("--vault", "--account", "--tags", "--format"):
        flags[arg] = args[i + 1]
        i += 2
        continue
    if arg == "--archive":
        flags[arg] = True
    else:
        positional.append(arg)
    i += 1

vault = flags.get("--vault", "V")


def path_for(title):
    return os.path.join(items_dir, title.replace("/", "__") + ".json")


def load_all():
    out = []
    for name in sorted(os.listdir(items_dir)):
        with open(os.path.join(items_dir, name)) as handle:
            out.append(json.load(handle))
    return out


def find(reference):
    """An item by title, or by id (the real op accepts both)."""
    path = path_for(reference)
    if os.path.exists(path):
        with open(path) as handle:
            return json.load(handle)
    for item in load_all():
        if item["id"] == reference:
            return item
    fail('"%s" isn\'t an item in the "%s" vault. Specify the item with its UUID, name, or domain.' % (reference, vault))


def counter():
    path = os.path.join(db, "counter")
    value = int(open(path).read()) + 1 if os.path.exists(path) else 1
    with open(path, "w") as handle:
        handle.write(str(value))
    return value


def write(item):
    with open(path_for(item["title"]), "w") as handle:
        json.dump(item, handle)


command = positional[:2]
rest = positional[2:]

if command == ["vault", "get"]:
    name = rest[0]
    if name == "missing":
        fail('"missing" isn\'t a vault in this account.')
    print(json.dumps({"id": "vault-1", "name": name}))
elif command == ["item", "list"]:
    tag = flags.get("--tags")
    listing = [
        {"id": item["id"], "title": item["title"], "tags": item.get("tags", [])}
        for item in load_all()
        if tag is None or tag in item.get("tags", [])
    ]
    print(json.dumps(listing, indent=2))
elif command == ["item", "get"] and rest == ["-"]:
    wanted = json.loads(sys.stdin.read())
    ids = {entry["id"] for entry in wanted}
    for item in load_all():
        if item["id"] in ids:
            print(json.dumps(item, indent=2))
elif command == ["item", "get"]:
    print(json.dumps(find(rest[0]), indent=2))
elif command == ["item", "create"] and rest == ["-"]:
    template = json.loads(sys.stdin.read())
    if os.path.exists(path_for(template["title"])):
        fail("duplicate title " + template["title"])
    for field in template.get("fields", []):
        field.setdefault("id", "f%d" % counter())
    template["id"] = "item%d" % counter()
    template["vault"] = {"name": vault}
    write(template)
    print(json.dumps({"id": template["id"]}))
elif command == ["item", "edit"] and rest[1:] == ["-"]:
    item = find(rest[0])
    template = json.loads(sys.stdin.read())
    # Like the real op: built-in fields (those with a purpose) are updated in
    # place, while the custom fields are replaced by the template's custom fields.
    builtin = [field for field in item["fields"] if field.get("purpose")]
    custom = []
    for incoming in template.get("fields", []):
        if incoming.get("purpose"):
            for field in builtin:
                if field.get("id") == incoming.get("id"):
                    field.update(incoming)
        else:
            incoming.setdefault("id", "f%d" % counter())
            custom.append(incoming)
    item["fields"] = builtin + custom
    write(item)
    print(json.dumps({"id": item["id"]}))
elif command == ["item", "delete"]:
    find(rest[0])
    os.remove(path_for(rest[0]))
else:
    fail("fake op: unsupported command: " + " ".join(args))

"""Command line.

    python -m privgate scan  ticket.txt            # what would be detected
    python -m privgate mask  ticket.txt            # sanitised text
    python -m privgate bench                       # detection benchmark vs naive regex
    python -m privgate serve --port 8010           # gateway + playground
"""
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

from .bench import run
from .engine import Engine


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(prog="privgate")
    ap.add_argument("--policy", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "mask"):
        p = sub.add_parser(name)
        p.add_argument("file", help="text file, or - for stdin")
    b = sub.add_parser("bench")
    b.add_argument("--docs", type=int, default=600)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8010)
    s.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args(argv)

    if a.cmd in ("scan", "mask"):
        text = sys.stdin.read() if a.file == "-" else Path(a.file).read_text(encoding="utf-8")
        eng = Engine(a.policy) if a.policy else Engine()
        if a.cmd == "scan":
            for e in eng.scan(text):
                print(f"{e.type:12s} {eng.action(e.type):9s} {e.value!r:40s} {e.confidence:.2f} {e.note}")
        else:
            r = eng.sanitize(text, uuid.uuid4().hex, raise_on_block=False)
            print(r.text)
            blocked = sorted({e.type for e in r.entities if eng.action(e.type) == "block"})
            if blocked:
                print(f"\n[!] a gateway would refuse this request: contains {', '.join(blocked)}", file=sys.stderr)
    elif a.cmd == "bench":
        res = run(a.docs)
        print(f"{'type':10s} {'gateway P/R/F1':>22s}   {'naive regex P/R/F1':>22s}")
        for t in res["gateway"]:
            g, n = res["gateway"][t], res["naive_regex"].get(t, {"precision": 0, "recall": 0, "f1": 0})
            print(f"{t:10s} {g['precision']:.3f} / {g['recall']:.3f} / {g['f1']:.3f}   {n['precision']:.3f} / {n['recall']:.3f} / {n['f1']:.3f}")
    else:
        import uvicorn

        uvicorn.run("privgate.gateway:app", host=a.host, port=a.port)


if __name__ == "__main__":
    main()

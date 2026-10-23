"""Command line.

    python -m privgate scan  ticket.txt            # what would be detected
    python -m privgate mask  ticket.txt            # sanitised text
    python -m privgate bench                       # detection benchmark vs naive regex
    python -m privgate serve --port 8010           # gateway + playground
"""
from __future__ import annotations

import argparse
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
    r = sub.add_parser("realdata", help="detection on Gretel's labelled financial documents")
    r.add_argument("--gretel", required=True, help="English_test parquet of gretelai/synthetic_pii_finance_multilingual")
    r.add_argument("--out", default="results/real_data.json")
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
    elif a.cmd == "realdata":
        import json

        from .realdata import run as realdata

        res = realdata(a.gretel)
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(res, indent=2))
        for lab, v in res["by_label"].items():
            if v["target_type"]:
                print(f"{lab:28s} {v['target_type']:9s} {v['masked_share']:6.1%} of {v['gold']}")
        print(f"targeted spans masked: {res['targeted_spans_masked']:.1%}")
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

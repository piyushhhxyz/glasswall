"""`pii-verify` - start the UI, or check a pair from the terminal."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from threading import Timer

from .config import Settings


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    url = f"http://{args.host}:{args.port}"
    settings = Settings.from_env()
    print(f"pii-verifier -> s3://{settings.bucket}/")
    print(f"  original: {settings.original_root or '(bucket root)'}")
    print(f"  redacted: {settings.redacted_root or '(bucket root)'}")
    print(f"  region:   {settings.region}")
    print(f"\nserving {url}\n")
    if not args.no_browser:
        # Fires once the server is accepting connections rather than before it.
        Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run("pii_verifier.app:app", host=args.host, port=args.port, log_level=args.log_level)
    return 0


def _check(args: argparse.Namespace) -> int:
    """Headless verification of one relative key, for scripting and CI."""
    from .extract import extract
    from .s3 import S3Browser
    from .scan import verify

    browser = S3Browser(Settings.from_env())
    texts = {}
    for side in ("original", "redacted"):
        payload, truncated, error = browser.get(side, args.relative)
        if error:
            print(f"error reading {side}: {error}", file=sys.stderr)
            return 2
        texts[side] = extract(args.relative, payload, truncated).text

    report = verify(texts["original"], texts["redacted"])
    if args.json:
        print(json.dumps(report.to_json(), indent=2))
    else:
        print(f"verdict: {report.verdict}")
        for key, value in report.stats.items():
            print(f"  {key}: {value}")
        for label, rows in (("LEAK", report.leaks), ("PARTIAL", report.partials)):
            for row in rows[:20]:
                site = (row.get("in_redacted") or [{}])[0]
                where = f" line {site['line']}" + (f" ({site['path']})" if site.get("path") else "") \
                    if site.get("line") else ""
                extra = ""
                if row.get("fragments"):
                    extra = "  survived: " + ", ".join(f["fragment"] for f in row["fragments"])
                print(f"  {label} [{row['severity']}] {row['type']}: "
                      f"{row['text'][:70]!r} x{row['occurrences']}{where}{extra}")
    # Non-zero exit on anything that survived, so this can gate a pipeline.
    return 1 if report.verdict in ("leak", "partial") else 0


def _audit(args: argparse.Namespace) -> int:
    """Verify a whole prefix and exit non-zero if anything survived."""
    from . import audit as audit_module
    from .s3 import S3Browser

    result = audit_module.run(
        S3Browser(Settings.from_env()), args.prefix,
        max_files=args.max_files, max_depth=args.max_depth,
    )
    payload = result.to_json()
    if args.json:
        print(json.dumps(payload, indent=2))
        return 1 if payload["flagged"] else 0

    print(f"checked {payload['checked']} paired file(s) under {args.prefix or '(root)'}")
    for verdict, count in sorted(payload["by_verdict"].items()):
        print(f"  {verdict}: {count}")
    for note in payload["notes"]:
        print(f"  note: {note}")
    for row in payload["files"]:
        if row["verdict"] not in ("leak", "partial"):
            continue
        print(f"\n{row['verdict'].upper()} [{row.get('severity')}] {row['relative']}")
        for finding in row.get("top", []):
            where = f" line {finding['line']}" if finding.get("line") else ""
            path = f" ({finding['path']})" if finding.get("path") else ""
            frags = ("  survived: " + ", ".join(finding["fragments"])) if finding.get("fragments") else ""
            print(f"    {finding['kind']:7} {finding['type']}: "
                  f"{finding['text'][:60]!r}{where}{path}{frags}")
    return 1 if payload["flagged"] else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pii-verify", description=__doc__)
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="run the local web UI")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--log-level", default="info")
    serve.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    serve.set_defaults(func=_serve)

    check = sub.add_parser("check", help="verify one relative key and exit non-zero on a leak")
    check.add_argument("relative", help="key relative to the two roots, e.g. slack/general/2023-01-01.json")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=_check)

    scan = sub.add_parser("audit", help="verify every paired file under a prefix")
    scan.add_argument("prefix", nargs="?", default="", help="prefix relative to the two roots")
    scan.add_argument("--max-files", type=int, default=200)
    scan.add_argument("--max-depth", type=int, default=6)
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=_audit)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        # Bare `pii-verify` should do the obvious thing.
        return _serve(parser.parse_args(["serve"]))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

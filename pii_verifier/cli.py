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
        for leak in report.leaks[:20]:
            print(f"  LEAK [{leak['severity']}] {leak['type']}: {leak['text'][:80]!r} x{leak['occurrences']}")
    # Non-zero exit on a leak so this can gate a pipeline.
    return 1 if report.verdict == "leak" else 0


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

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        # Bare `pii-verify` should do the obvious thing.
        return _serve(parser.parse_args(["serve"]))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

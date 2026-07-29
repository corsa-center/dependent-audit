#!/usr/bin/env python3
"""A stand-in for audit_dependents.py used only in CI.

The real crawler needs Sourcegraph/GitHub tokens and hits external APIs, which is
unsuitable for CI. The service invokes its crawler as
``[python, AUDIT_SCRIPT, --repo … --name … --out … <flags>]``; this fake honors
that exact contract — it accepts (and ignores) every flag, then writes a minimal
but well-formed dependency graph to ``--out`` and one SPDX snippet, so the full
service path (nginx → gunicorn → shared volume → worker → result) can be
exercised end-to-end. Point the service at it with ``AUDIT_SCRIPT=/app/fake_audit.py``.
"""

import argparse
import json
import os


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--out", default="dependency_graph.json")
    p.add_argument("--ecosystem", default="cpp")
    # Swallow every other flag the service may pass through.
    args, _unknown = p.parse_known_args()

    graph = {
        "meta": {
            "root": args.repo,
            "ecosystem": args.ecosystem,
            "schemaVersion": "2.0",
            "fake": True,
        },
        "nodes": [
            {
                "data": {
                    "packageName": args.name,
                    "packageOwner": args.repo.split("/")[0],
                    "depth": 0,
                    "papers": [],
                }
            }
        ],
        "edges": [],
    }
    with open(args.out, "w") as f:
        json.dump(graph, f, indent=2)

    # Emit a snippet so the /spdx endpoint has something to serve.
    os.makedirs("spdx_snippets", exist_ok=True)
    with open(os.path.join("spdx_snippets", "fake.spdx.json"), "w") as f:
        json.dump({"spdxVersion": "SPDX-2.3", "name": args.name}, f)


if __name__ == "__main__":
    main()

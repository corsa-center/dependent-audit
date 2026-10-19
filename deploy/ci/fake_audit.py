#!/usr/bin/env python3
"""A stand-in for audit_dependents.py used in CI and local UI development.

The real crawler needs Sourcegraph/GitHub tokens and hits external APIs, which is
unsuitable for CI. The service invokes its crawler as
``[python, AUDIT_SCRIPT, --repo … --name … --out … --events-file … <flags>]``;
this fake honors that exact contract — it accepts (and ignores) every other
flag, streams the full progress-event catalogue (with ``FAKE_AUDIT_DELAY``
seconds between steps, default 0.3), then writes a small but realistic
dependency graph to ``--out`` plus one SPDX snippet per edge. That exercises the
full service path (nginx → gunicorn → shared volume → worker → SSE → result)
end-to-end, and gives the frontend something to render.
Point the service at it with ``AUDIT_SCRIPT=/app/fake_audit.py``.

``FAKE_AUDIT_FAIL=1`` makes it exit non-zero after the search phase.
"""

import argparse
import json
import os
import sys
import time

DELAY = float(os.environ.get("FAKE_AUDIT_DELAY", "0.3"))


class Events:
    """Minimal twin of audit_dependents.ProgressEmitter (same envelope)."""

    def __init__(self, path):
        self.path = path
        self.seq = 0
        if path and os.path.exists(path):
            with open(path, "rb") as f:
                self.seq = f.read().count(b"\n")

    def emit(self, type_, **data):
        if not self.path:
            return
        line = (
            json.dumps(
                {
                    "seq": self.seq,
                    "ts": round(time.time(), 3),
                    "type": type_,
                    "src": "crawler",
                    "data": data,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)
        self.seq += 1


def _paper(
    doi, title, tier, score, relation="citing", depth=1, prov="reverse_citation"
):
    return {
        "title": title,
        "doi": doi,
        "journal": "Journal of Fake Results",
        "url": f"https://doi.org/{doi}",
        "citations": 12,
        "citationDepth": depth,
        "relation": relation,
        "authors": ["A. Author", "B. Author"],
        "year": 2021,
        "concepts": ["compression", "floating point"],
        "provenance": [prov],
        "relevanceScore": score,
        "relevanceTier": tier,
        "relevanceEvidence": {"provenance": prov, "authorOverlap": 1},
    }


def _consumers(root):
    owner = root.split("/")[0]
    return [
        # id, confidence, score, relationship, layer, matches, stars, license, fork
        ("acme/solver", "high", 9.5, "DEPENDS_ON", 4, 42, 1830, "BSD-3-Clause", False),
        ("sci/viz-toolkit", "high", 8.1, "DEPENDS_ON", 3, 17, 950, "Apache-2.0", False),
        ("hpc/io-lib", "medium", 5.2, "DEPENDS_ON", 3, 6, 210, "MIT", False),
        ("student/thesis-code", "low", 1.8, "DEPENDS_ON", 2, 1, 3, "None", False),
        ("bundle/mono-repo", "medium", 4.4, "VENDORED", 2, 88, 75, "GPL-3.0", False),
        (f"{owner}-fork/mirror", "low", 2.0, "MIRROR", 2, 30, 1, "BSD-3-Clause", True),
    ]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--out", default="dependency_graph.json")
    p.add_argument("--ecosystem", default="cpp")
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--events-file")
    # Swallow every other flag the service may pass through.
    args, _unknown = p.parse_known_args()

    ev = Events(args.events_file)
    t0 = time.monotonic()
    root = args.repo.replace("github.com/", "")
    owner, name = (root.split("/", 1) + [args.name])[:2]

    def step():
        time.sleep(DELAY)

    print(
        f"[INFO] [Depth 0] {root} : Booting Ecosystem Audit Engine (fake)",
        file=sys.stderr,
        flush=True,
    )
    ev.emit(
        "run_started",
        runId="fake-run",
        root=root,
        name=args.name,
        depth=args.depth,
        ecosystem=args.ecosystem,
        citations=True,
        sgCount="5000",
        eventsVersion=1,
    )
    ev.emit("phase", phase="root_metadata", state="start", repo=root)
    step()
    seminal = _paper(
        "10.0000/fake.seminal",
        f"{args.name}: the seminal paper",
        "high",
        9.0,
        relation="seminal",
        depth=0,
        prov="seminal",
    )
    root_node = {
        "id": root,
        "label": name,
        "type": "library",
        "data": {
            "packageName": name,
            "packageOwner": owner,
            "originUrl": f"https://github.com/{root}",
            "commitSha": "0" * 40,
            "depth": 0,
            "snippetPath": "",
            "stars": 512,
            "contributors": 40,
            "commits": 2300,
            "lastUpdate": "2026-09-01T00:00:00Z",
            "latestRelease": "1.0.0",
            "license": "BSD-3-Clause",
            "isFork": False,
            "description": f"The {args.name} project (fake audit data).",
            "papers": [
                seminal,
                _paper("10.0000/fake.citer1", "Using it at scale", "high", 7.5),
                _paper(
                    "10.0000/fake.citer2",
                    "A tangential mention",
                    "medium",
                    4.0,
                    prov="keyword_search",
                ),
            ],
            "paperDiagnostics": {"complete": True, "warnings": []},
            "confidence": None,
            "confidenceScore": 0,
            "evidence": {},
            "identifiers": [],
            "provenance": [],
            "evidenceLayer": None,
            "layers": [],
            "relationship": None,
            "matchCount": 0,
        },
    }
    ev.emit("phase", phase="root_metadata", state="end", repo=root)
    ev.emit(
        "node",
        id=root,
        label=name,
        type="library",
        depth=0,
        stars=512,
        license="BSD-3-Clause",
        isFork=False,
        description=root_node["data"]["description"],
        papers={"total": 3, "seminal": 1, "high": 2, "medium": 1},
        papersComplete=True,
    )

    nodes, edges = [root_node], []
    if args.depth >= 1:
        ev.emit("node_start", repo=root, depth=0, chain=[root], processed=1, queued=0)
        ev.emit("phase", phase="identifiers", state="start", repo=root)
        step()
        ev.emit(
            "phase",
            phase="identifiers",
            state="end",
            repo=root,
            detail={
                "count": 12,
                "byKind": {
                    "header_path": 9,
                    "cmake_package": 1,
                    "cmake_target": 1,
                    "vcs_ref": 1,
                },
            },
        )
        ev.emit("phase", phase="specificity", state="start", repo=root)
        step()
        ev.emit(
            "phase",
            phase="specificity",
            state="end",
            repo=root,
            detail={"patterns": 11, "probes": 3, "cacheHits": 6},
        )
        ev.emit("phase", phase="search", state="start", repo=root)
        consumers = _consumers(root)
        for i, matches in enumerate((40, 110, 184), 1):
            step()
            ev.emit(
                "search_progress",
                repo=root,
                matches=matches,
                lines=matches + 9,
                consumers=2 * i,
                elapsedSec=round(time.monotonic() - t0, 1),
                final=False,
            )
        ev.emit(
            "search_progress",
            repo=root,
            matches=184,
            lines=193,
            consumers=len(consumers),
            elapsedSec=round(time.monotonic() - t0, 1),
            final=True,
        )
        ev.emit(
            "phase",
            phase="search",
            state="end",
            repo=root,
            detail={"matches": 184, "consumers": len(consumers)},
        )
        print(
            f"[WARNING] [Depth 0] {root} : fake warning: result limit not hit",
            file=sys.stderr,
            flush=True,
        )
        ev.emit(
            "log",
            level="WARNING",
            repo=root,
            depth=0,
            extra=None,
            message="Example warning from the fake crawler (nothing is wrong).",
        )

        if os.environ.get("FAKE_AUDIT_FAIL"):
            print("fake crawler: failing on request", file=sys.stderr)
            ev.emit("error", message="fake failure requested", excType="RuntimeError")
            sys.exit(3)

        ev.emit("phase", phase="scoring", state="start", repo=root)
        ev.emit(
            "phase",
            phase="scoring",
            state="end",
            repo=root,
            detail={"consumers": len(consumers)},
        )
        ev.emit(
            "candidates",
            parent=root,
            depth=1,
            total=len(consumers),
            batchIndex=0,
            batchCount=1,
            batch=[
                {
                    "id": c[0],
                    "confidence": c[1],
                    "confidenceScore": c[2],
                    "relationship": c[3],
                    "evidenceLayer": c[4],
                    "matchCount": c[5],
                }
                for c in consumers
            ],
        )
        ev.emit(
            "phase",
            phase="enrich",
            state="start",
            repo=root,
            detail={"total": len(consumers)},
        )
        os.makedirs("spdx_snippets", exist_ok=True)
        for done, (
            cid,
            conf,
            score,
            rel,
            layer,
            matches,
            stars,
            lic,
            fork,
        ) in enumerate(consumers, 1):
            ev.emit(
                "enrich_progress",
                parent=root,
                done=done,
                total=len(consumers),
                repo=cid,
            )
            step()
            c_owner, c_name = cid.split("/")
            evidence = {"include": matches}
            idents = [f"{args.name}/{args.name}.h"]
            layers = sorted({2, layer})
            if layer >= 3:
                evidence["find_package"] = 2
                idents.append(args.name)
            if layer >= 4:
                evidence["vcs_ref"] = 1
                idents.append(root)
            snippet = f"spdx_snippets/{c_owner}_{c_name}.spdx.json"
            with open(snippet, "w") as f:
                json.dump(
                    {
                        "spdxVersion": "SPDX-2.3",
                        "name": f"{c_name} Dependency Manifest",
                        "provider": root,
                    },
                    f,
                )
            papers = []
            if conf == "high":
                papers = [
                    _paper(
                        f"10.0000/fake.{c_name}",
                        f"{c_name}: a paper",
                        "medium",
                        5.0,
                        relation="seminal",
                        depth=0,
                        prov="seminal",
                    )
                ]
            data = {
                "packageName": c_name,
                "packageOwner": c_owner,
                "originUrl": f"https://github.com/{cid}",
                "commitSha": "1" * 40,
                "depth": 1,
                "snippetPath": snippet,
                "stars": stars,
                "contributors": max(1, stars // 40),
                "commits": 100 + stars,
                "lastUpdate": "2026-08-15T00:00:00Z",
                "latestRelease": "",
                "license": lic,
                "isFork": fork,
                "description": f"Fake consumer {c_name} of {args.name}.",
                "papers": papers,
                "paperDiagnostics": {"complete": True, "warnings": []},
                "confidence": conf,
                "confidenceScore": score,
                "evidence": evidence,
                "identifiers": idents,
                "provenance": ["header_scan"],
                "evidenceLayer": layer,
                "layers": layers,
                "relationship": rel,
                "matchCount": matches,
            }
            nodes.append({"id": cid, "label": c_name, "type": "consumer", "data": data})
            edge = {
                "source": cid,
                "target": root,
                "evidence": evidence,
                "identifiers": idents,
                "provenance": ["header_scan"],
                "evidenceLayer": layer,
                "layers": layers,
                "relationship": rel,
                "confidence": conf,
                "confidenceScore": score,
                "matchCount": matches,
            }
            edges.append(edge)
            ev.emit(
                "node",
                id=cid,
                label=c_name,
                type="consumer",
                depth=1,
                stars=stars,
                license=lic,
                isFork=fork,
                description=data["description"],
                confidence=conf,
                confidenceScore=score,
                relationship=rel,
                evidenceLayer=layer,
                matchCount=matches,
                snippetPath=snippet,
                papers={
                    "total": len(papers),
                    "seminal": len(papers),
                    **({"medium": 1} if papers else {}),
                },
                papersComplete=True,
            )
            ev.emit(
                "edge",
                source=cid,
                target=root,
                relationship=rel,
                confidence=conf,
                confidenceScore=score,
                evidenceLayer=layer,
                layers=layers,
                matchCount=matches,
                evidence=evidence,
                identifiers=idents,
                identifiersTotal=len(idents),
            )
        ev.emit(
            "phase",
            phase="enrich",
            state="end",
            repo=root,
            detail={"total": len(consumers)},
        )

    ev.emit("phase", phase="write", state="start", repo=root)
    completeness = {
        "complete": True,
        "warnings": [],
        "discovery": {"complete": True, "warnings": []},
        "citations": {"complete": True, "incompleteNodes": []},
        "seminalIndex": {"complete": True, "jossPagesFailed": 0},
    }
    graph = {
        "meta": {
            "root": root,
            "ecosystem": args.ecosystem,
            "schemaVersion": "2.3",
            "completeness": completeness,
            "fake": True,
        },
        "nodes": nodes,
        "edges": edges,
    }
    with open(args.out, "w") as f:
        json.dump(graph, f, indent=2)
    if not edges:  # keep /spdx servable even for depth 0
        os.makedirs("spdx_snippets", exist_ok=True)
        with open(os.path.join("spdx_snippets", "fake.spdx.json"), "w") as f:
            json.dump({"spdxVersion": "SPDX-2.3", "name": args.name}, f)
    ev.emit("phase", phase="write", state="end", repo=root)
    ev.emit(
        "result",
        complete=True,
        warnings=[],
        nodes=len(nodes),
        edges=len(edges),
        elapsedSec=round(time.monotonic() - t0, 1),
        completeness=completeness,
    )
    print(
        f"[INFO] [Depth 0] {root} : Audit graph generation completed (COMPLETE).",
        file=sys.stderr,
        flush=True,
    )


if __name__ == "__main__":
    main()

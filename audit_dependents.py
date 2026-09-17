import os
import time
import json
import argparse
import requests
import re
import concurrent.futures
import math
import uuid
import logging
from collections import deque, defaultdict
from dataclasses import dataclass

SNIPPETS_DIR = "spdx_snippets"
SOURCEGRAPH_URL = "https://sourcegraph.com/.api/graphql"
SOURCEGRAPH_STREAM_URL = "https://sourcegraph.com/.api/search/stream"
JOSS_API_URL = "https://joss.theoj.org/papers/published.json"
CROSSREF_API_URL = "https://api.crossref.org/works/"
OPENCITATIONS_API_URL = "https://opencitations.net/index/api/v1/citations/"
DOI_REGEX = r"\b(10\.\d{4,9}/[-._;()/:A-Z0-9]+)\b"

# Reverse-citation crawl bounds. Depth 1 == "direct citers of the seminal
# paper" (the historical behavior); higher depths crawl citers-of-citers.
# The per-level / total caps are load-bearing: citation fan-out is explosive.
CITATION_DEFAULT_DEPTH = 1
CITATION_MAX_PER_LEVEL = 500
CITATION_MAX_TOTAL = 2000

OPENALEX_API_URL = "https://api.openalex.org/works"

# Longest Retry-After (seconds) an optional publication call will honor before
# giving up. A quota-limited service can send a multi-hour Retry-After; honoring
# it literally would stall the whole crawl for a *best-effort* enrichment call,
# so beyond this cap we abandon that one call and degrade to empty metadata.
HTTP_RETRY_AFTER_CAP = 60

# Paper-relevance scoring. Mirrors the consumer corroboration scorer
# (_score_consumer): each independent signal is a "kind", the strongest one
# drives the score, and additional kinds corroborate. Discovery *provenance* is
# the dominant signal — how a DOI was found says the most about whether it truly
# references this project. Vocabulary, strongest -> weakest:
#   seminal            the repo's own paper (always kept)
#   reverse_citation   OpenAlex `cites:doi:` reverse lookup off a seminal DOI
#   reverse_citation_oc OpenCitations reverse lookup (same signal, other source)
#   text_scrape        a raw DOI mined from the repo's own text
#   web_scrape         a DOI scraped from a linked homepage
#   keyword_search     bare OpenAlex full-text `search=<term>` hit (weakest;
#                      needs corroboration to clear `low` — the "zfp" fix)
PROVENANCE_WEIGHT = {
    "seminal": 6,
    "reverse_citation": 5,
    "reverse_citation_oc": 5,
    "text_scrape": 4,
    "web_scrape": 3,
    "keyword_search": 1,
}

# Common English + academic-boilerplate tokens excluded from the repo "profile"
# term set, so term-overlap measures topical similarity, not shared filler.
PROFILE_STOPWORDS = frozenset(
    """
    the a an and or of to in for on with without by from as is are was were be been
    being at this that these those it its into over under out up down off then than
    but not no nor so such can may might will would should could must have has had do
    does did done using use used via not we our you your they their he she his her
    library software package tool toolkit framework project code source data file
    files based provide provides provided support supports supported implementation
    implements interface api version release build make cmake python cpp header
    include https http github com www org io new open free general purpose simple fast
    high performance easy also more most other some any all one two three
    """.split()
)

# Paper-relevance scorer weights / tiers (parallel to KIND_WEIGHTS + TIER_*).
PAPER_AUTHOR_OVERLAP_WEIGHT = 4.0
PAPER_TERM_OVERLAP_WEIGHT = 3.0  # scaled by matched-fraction
PAPER_CONCEPT_OVERLAP_WEIGHT = 3.0
PAPER_VENUE_MATCH_WEIGHT = 2.0
PAPER_CORROBORATION_BONUS = 1.5
PAPER_VOLUME_CAP = 2.0
PAPER_TIER_HIGH = 5.5
PAPER_TIER_MEDIUM = 3.0
# A paper whose heuristic score lands within this margin *below* a tier cutoff
# is "borderline" and eligible for the optional LLM tie-breaker.
PAPER_LLM_BORDERLINE_MARGIN = 1.0
PAPER_TIER_ORDER = {"low": 0, "medium": 1, "high": 2}


class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "run_id": getattr(record, "run_id", "UNKNOWN"),
            "plugin": getattr(record, "plugin", "UNKNOWN"),
            "root_repo": getattr(record, "root_repo", "UNKNOWN"),
            "depth": getattr(record, "depth", 0),
            "chain": getattr(record, "chain", []),
            "message": record.getMessage(),
        }
        if hasattr(record, "extra_meta") and record.extra_meta:
            log_record["metadata"] = record.extra_meta
        return json.dumps(log_record)


class TerseFormatter(logging.Formatter):
    def format(self, record):
        chain_str = " -> ".join(getattr(record, "chain", ["UNKNOWN"]))
        return f"[{record.levelname}] [Depth {getattr(record, 'depth', 0)}] {chain_str} : {record.getMessage()}"


class ContextAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = self.extra.copy()
        if "extra" in kwargs:
            extra["extra_meta"] = kwargs.pop("extra")
        kwargs["extra"] = extra
        return msg, kwargs


def setup_logger(verbose):
    logger = logging.getLogger("DependencyAudit")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter() if verbose else TerseFormatter())
    logger.addHandler(handler)
    return logger


class CitationDiagnostics:
    """Per-node record of everything that made a citation search *partial*, so
    an incomplete result is reported rather than silently smaller.

    Determinism depends on this. Two runs over the same live data should agree;
    the things that break that promise are transient failures (rate limits,
    timeouts) and bounded caps that truncate the crawl. When one of those does
    cause divergence, it must be surfaced — a swallowed 429 is exactly how two
    users get different graphs with no way to tell which is complete."""

    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    REQUEST_ERROR = "request_error"
    BAD_RESPONSE = "bad_response"

    def __init__(self):
        self.http_failures = {}  # channel -> {kind: count}
        self.caps_hit = set()  # e.g. {"citation_per_level", "citation_total"}
        self.dois_seen = 0
        self.dois_unresolved = 0  # DOI produced no usable metadata record
        self.seminal_found = 0

    def record_http(self, channel, kind):
        channel = channel or "unknown"
        kinds = self.http_failures.setdefault(channel, {})
        kinds[kind] = kinds.get(kind, 0) + 1

    def record_cap(self, name):
        self.caps_hit.add(name)

    @property
    def complete(self):
        return not self.http_failures and not self.caps_hit

    def warnings(self):
        """Deterministic, human-readable account of what made this partial."""
        out = []
        for channel in sorted(self.http_failures):
            kinds = self.http_failures[channel]
            detail = ", ".join(f"{k}×{kinds[k]}" for k in sorted(kinds))
            out.append(
                f"{channel}: {sum(kinds.values())} dropped request(s) ({detail})"
            )
        for cap in sorted(self.caps_hit):
            out.append(f"cap '{cap}' reached; crawl truncated (results may vary)")
        if self.dois_unresolved:
            out.append(
                f"{self.dois_unresolved} DOI(s) could not be resolved to metadata"
            )
        return out

    def summary(self):
        return {
            "complete": self.complete,
            "warnings": self.warnings(),
            "httpFailures": {
                c: dict(sorted(self.http_failures[c].items()))
                for c in sorted(self.http_failures)
            },
            "capsHit": sorted(self.caps_hit),
            "doisSeen": self.dois_seen,
            "doisUnresolved": self.dois_unresolved,
            "seminalFound": self.seminal_found,
        }


def _tokenize(text):
    """Lowercase, split on non-alphanumerics, drop stopwords and short tokens."""
    if not text:
        return []
    return [
        t
        for t in re.split(r"[^a-z0-9]+", text.lower())
        if len(t) >= 3 and t not in PROFILE_STOPWORDS
    ]


def _significant_terms(text, exclude=frozenset(), top_n=40):
    """Top-N most frequent significant tokens in `text`, minus `exclude`.

    `exclude` carries the bare project-name token(s): a colliding name like
    `zfp` must never enter the profile term set, or a keyword-search hit on an
    unrelated `zfp` paper would corroborate itself into a higher tier."""
    freq = defaultdict(int)
    for tok in _tokenize(text):
        if tok in exclude:
            continue
        freq[tok] += 1
    ranked = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))
    return {tok for tok, _ in ranked[:top_n]}


class PublicationPlugin:
    def __init__(self, email):
        self.email = email
        # Set per-node by CitationEngine so failures on shared plugins are
        # attributed to the node being processed. None outside a scored run.
        self.diag = None

    def initialize(self):
        pass

    def _note_failure(self, channel, kind, log, url, attempt):
        if self.diag is not None:
            self.diag.record_http(channel, kind)
        if log:
            log.debug(
                f"{channel or 'http'} call dropped ({kind})",
                extra={"url": url, "attempt": attempt},
            )

    def _http_get_json(
        self, url, params=None, headers=None, timeout=10, max_attempts=4,
        log=None, channel=None,
    ):
        """GET returning parsed JSON with exponential backoff on 429/5xx and
        transient request errors. Modeled on `_graphql_query`. Returns the
        decoded body on success, or None once attempts are exhausted / on a
        non-retryable non-200. Never raises — publication lookups degrade to
        empty rather than aborting the crawl.

        A definitive negative (a non-retryable non-200 such as 404 "not found")
        is NOT recorded as a failure: it is a complete answer. Only exhausted
        retries, an over-cap Retry-After, and an unparseable 200 count against
        completeness (via `channel`), because those *drop* data that another run
        might have gotten."""
        backoff = 2
        for attempt in range(1, max_attempts + 1):
            try:
                resp = requests.get(
                    url, params=params, headers=headers, timeout=timeout
                )
            except requests.exceptions.RequestException as e:
                if log:
                    log.debug(
                        "HTTP request failed",
                        extra={"url": url, "attempt": attempt, "error": str(e)},
                    )
                if attempt == max_attempts:
                    self._note_failure(
                        channel, CitationDiagnostics.REQUEST_ERROR, log, url, attempt
                    )
                    return None
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                kind = (
                    CitationDiagnostics.RATE_LIMITED
                    if resp.status_code == 429
                    else CitationDiagnostics.SERVER_ERROR
                )
                if attempt == max_attempts:
                    self._note_failure(channel, kind, log, url, attempt)
                    return None
                wait = backoff
                retry_after = resp.headers.get("Retry-After")
                if retry_after and retry_after.strip().isdigit():
                    ra = int(retry_after.strip())
                    # A quota cool-off longer than the cap won't clear within a
                    # sensible run; abandon this optional call rather than stall.
                    if ra > HTTP_RETRY_AFTER_CAP:
                        self._note_failure(channel, kind, log, url, attempt)
                        if log:
                            log.debug(
                                f"HTTP {resp.status_code}; Retry-After {ra}s "
                                "exceeds cap, skipping call",
                                extra={"url": url, "attempt": attempt},
                            )
                        return None
                    wait = max(wait, ra)
                if log:
                    log.debug(
                        f"HTTP {resp.status_code}; backing off {wait}s",
                        extra={"url": url, "attempt": attempt},
                    )
                time.sleep(wait)
                backoff = min(backoff * 2, 30)
                continue

            if resp.status_code != 200:
                return None  # definitive negative (e.g. 404) — a complete answer
            try:
                return resp.json()
            except ValueError:
                self._note_failure(
                    channel, CitationDiagnostics.BAD_RESPONSE, log, url, attempt
                )
                return None
        return None


class SeminalDiscoveryPlugin(PublicationPlugin):
    def discover_seminal(self, repo_url, repo_meta, log):
        return set()


class JOSSPublicationPlugin(SeminalDiscoveryPlugin):
    def initialize(self):
        self.joss_map = {}
        # Run-level completeness: a dropped JOSS page can hide a seminal DOI for
        # *any* node, so two users with different page failures could diverge.
        self.pages_total = 299
        self.pages_failed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            for page_data in executor.map(self._fetch_joss_page, list(range(1, 300))):
                if page_data is None:  # request failed (distinct from empty page)
                    self.pages_failed += 1
                    continue
                if not page_data:  # legitimately empty page (past the last)
                    continue
                for paper in page_data:
                    repo_url = (
                        paper.get("repo_url", "")
                        .rstrip("/")
                        .replace(".git", "")
                        .replace("http://", "https://")
                    )
                    if repo_url:
                        self.joss_map[repo_url.lower()] = {
                            "title": paper.get("title"),
                            "doi": paper.get("doi"),
                            "joss_pdf": paper.get("paper_url"),
                            "journal": "JOSS",
                        }

    def _fetch_joss_page(self, page):
        """Return the page's JSON list on success, [] for an empty page, or
        None when the request itself failed (so init can count it)."""
        try:
            resp = requests.get(f"{JOSS_API_URL}?page={page}", timeout=10)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    def discover_seminal(self, repo_url, repo_meta, log):
        paper = self.joss_map.get(repo_url.lower())
        if paper and paper.get("doi"):
            log.debug("Found Seminal DOI via JOSS", extra={"doi": paper.get("doi")})
            return {paper.get("doi")}
        return set()


class CFFPublicationPlugin(SeminalDiscoveryPlugin):
    def discover_seminal(self, repo_url, repo_meta, log):
        cff_text = repo_meta.get("cff")
        if not cff_text:
            return set()
        dois = set(
            re.findall(
                r'(?:doi|identifier)\s*:\s*[\'"]?(10\.\d{4,9}/[-._;()/:A-Z0-9]+)[\'"]?',
                cff_text,
                re.IGNORECASE,
            )
        )
        if dois:
            log.debug("Found Seminal DOIs via CITATION.cff", extra={"dois": list(dois)})
        return dois


class ZenodoPublicationPlugin(SeminalDiscoveryPlugin):
    def discover_seminal(self, repo_url, repo_meta, log):
        dois = set()
        for jkey in ["zenodo", "zenodo_alt", "codemeta"]:
            if repo_meta.get(jkey):
                try:
                    data = json.loads(repo_meta[jkey])
                    doi = data.get("doi") or data.get("identifier")
                    if doi and doi.startswith("10."):
                        dois.add(doi)
                except:
                    pass
        readme = repo_meta.get("readme", "")
        dois.update(re.findall(r"(10\.5281/zenodo\.\d+)", readme, re.IGNORECASE))
        if dois:
            log.debug(
                "Found Seminal DOIs via Zenodo/Codemeta", extra={"dois": list(dois)}
            )
        return dois


class TextMatchPublicationPlugin(PublicationPlugin):
    def discover_dois(self, all_text, log):
        matches = set(re.findall(DOI_REGEX, all_text, re.IGNORECASE))
        return matches


class WebScrapePublicationPlugin(PublicationPlugin):
    def discover_dois(self, target_urls, log):
        found_dois = set()
        ignore = ["github.com", "orcid.org", "opensource.org", "spdx.org", "w3.org"]
        for u in target_urls:
            if not u.startswith("http"):
                continue
            clean_url = u.strip().strip("'").strip('"')
            if any(domain in clean_url for domain in ignore) or any(
                clean_url.endswith(ext)
                for ext in [".pdf", ".zip", ".tar.gz", ".png", ".jpg"]
            ):
                continue
            try:
                resp = requests.get(
                    clean_url,
                    headers={"User-Agent": "DependencyAuditBot/1.0"},
                    timeout=5,
                )
                if resp.status_code == 200 and "text/html" in resp.headers.get(
                    "Content-Type", ""
                ):
                    found_dois.update(re.findall(DOI_REGEX, resp.text, re.IGNORECASE))
            except:
                pass
        return found_dois


class OpenAlexPublicationPlugin(PublicationPlugin):
    @staticmethod
    def _deinvert_abstract(inv_index):
        """Reconstruct plain abstract text from OpenAlex's inverted index
        (`{token: [positions...]}`). Returns "" when absent/malformed."""
        if not isinstance(inv_index, dict) or not inv_index:
            return ""
        positioned = []
        for token, positions in inv_index.items():
            if not isinstance(positions, list):
                continue
            for pos in positions:
                if isinstance(pos, int):
                    positioned.append((pos, token))
        if not positioned:
            return ""
        positioned.sort()
        return " ".join(token for _, token in positioned)

    @classmethod
    def _parse_work(cls, work, provenance):
        """Extract the scoring-relevant surface of an OpenAlex work.

        `provenance` tags which channel surfaced the work; it is stamped onto
        the returned meta so callers can merge channels for one DOI."""
        doi = (work.get("doi") or "").replace("https://doi.org/", "")
        authors = []
        for a in work.get("authorships", []) or []:
            name = (a.get("author") or {}).get("display_name")
            if name:
                authors.append(name)
        concepts = [
            c.get("display_name")
            for c in (work.get("concepts") or [])
            if c.get("display_name")
        ]
        for t in work.get("topics") or []:
            if t.get("display_name"):
                concepts.append(t.get("display_name"))
        venue = ""
        primary = work.get("primary_location") or {}
        source = primary.get("source") or {}
        venue = source.get("display_name") or (
            (work.get("host_venue") or {}).get("display_name") or ""
        )
        return {
            "doi": doi,
            "title": work.get("title") or "",
            "abstract": cls._deinvert_abstract(
                work.get("abstract_inverted_index")
            ),
            "authors": authors,
            "concepts": concepts,
            "year": work.get("publication_year"),
            "venue": venue,
            "openalex_citations": work.get("cited_by_count", 0),
            "openalex_id": work.get("id"),
            "provenance": {provenance},
        }

    def _paginate_works(self, params, provenance, log):
        """Cursor-paginate an OpenAlex /works query, yielding parsed work meta
        keyed by normalized DOI."""
        out = {}
        cursor = "*"
        while cursor:
            data = self._http_get_json(
                OPENALEX_API_URL,
                params={
                    **params,
                    "mailto": self.email,
                    "per-page": 50,
                    "cursor": cursor,
                },
                timeout=10,
                log=log,
                channel="openalex",
            )
            if not data:
                break
            works = data.get("results", [])
            if not works:
                break
            for work in works:
                meta = self._parse_work(work, provenance)
                if meta["doi"]:
                    out[meta["doi"]] = meta
            cursor = data.get("meta", {}).get("next_cursor")
        return out

    def seed_search(self, target_urls, keywords, log):
        """One-shot full-text seed: works mentioning the target URLs / keywords.
        Returns {doi: meta} tagged `keyword_search`."""
        found = {}
        search_terms = {
            f'"{u.replace("https://", "").replace("http://", "").rstrip("/")}"'
            for u in target_urls
            if u
        }
        if keywords:
            for kw in keywords:
                search_terms.add(f'"{kw}"')
            log.info(
                f"Injecting explicit academic keywords into OpenAlex search: {keywords}"
            )

        # Sorted so the DOI whose meta "wins" a setdefault collision is stable
        # across runs (determinism), not dependent on set-iteration order.
        for term in sorted(search_terms):
            for doi, meta in self._paginate_works(
                {"search": term}, "keyword_search", log
            ).items():
                found.setdefault(doi, meta)
        return found

    def discover_citing(self, dois, log):
        """Reverse-citation lookup: works that cite any DOI in `dois`.
        Returns {doi: meta} tagged `reverse_citation`."""
        found = {}
        for doi in dois:
            log.debug("OpenAlex reverse-citation lookup", extra={"doi": doi})
            for cdoi, meta in self._paginate_works(
                {"filter": f"cites:doi:{doi}"}, "reverse_citation", log
            ).items():
                found.setdefault(cdoi, meta)
        return found

    def fetch_by_doi(self, doi, log):
        """Backfill a single work's meta by DOI. Used when a DOI arrived via a
        non-OpenAlex channel (text/web scrape, OpenCitations) but we still want
        its authors/concepts/abstract for relevance scoring."""
        data = self._http_get_json(
            f"{OPENALEX_API_URL}/https://doi.org/{doi}",
            params={"mailto": self.email},
            timeout=10,
            log=log,
            channel="openalex",
        )
        if not data or not isinstance(data, dict) or data.get("error"):
            return None
        return self._parse_work(data, "backfill")


class OpenCitationsPlugin(PublicationPlugin):
    def citing_dois(self, dois, log):
        found_dois = set()
        for doi in dois:
            log.debug("OpenCitations reverse-citation lookup", extra={"doi": doi})
            data = self._http_get_json(
                f"{OPENCITATIONS_API_URL}{doi}", timeout=10, log=log,
                channel="opencitations",
            )
            if isinstance(data, list):
                for item in data:
                    if item.get("citing"):
                        found_dois.add(item["citing"])
        return found_dois


class CrossrefPublicationPlugin(PublicationPlugin):
    @staticmethod
    def _strip_jats(abstract):
        """Crossref abstracts arrive wrapped in JATS XML; strip the tags."""
        if not abstract:
            return ""
        text = re.sub(r"<[^>]+>", " ", abstract)
        return re.sub(r"\s+", " ", text).strip()

    def resolve_doi(self, doi, log):
        data = self._http_get_json(
            f"{CROSSREF_API_URL}{doi}",
            headers={"User-Agent": f"DependencyAuditBot/1.0 (mailto:{self.email})"},
            timeout=5,
            log=log,
            channel="crossref",
        )
        if not data:
            return None
        item = data.get("message", {})
        titles = item.get("title") or [""]
        containers = item.get("container-title") or ["Unknown"]
        authors = []
        for a in item.get("author", []) or []:
            name = " ".join(
                filter(None, [a.get("given"), a.get("family")])
            ).strip()
            if name:
                authors.append(name)
        year = None
        parts = (item.get("published") or item.get("issued") or {}).get(
            "date-parts"
        )
        if isinstance(parts, list) and parts and isinstance(parts[0], list) and parts[0]:
            year = parts[0][0]
        return {
            "title": titles[0] if titles else "",
            "doi": doi,
            "journal": containers[0] if containers else "Unknown",
            "citations": item.get("is-referenced-by-count", 0),
            "url": item.get("URL"),
            "authors": authors,
            "subjects": item.get("subject", []) or [],
            "year": year,
            "abstract": self._strip_jats(item.get("abstract", "")),
        }


class PaperRelevanceScorer:
    """Scores how likely a discovered paper truly references *this* project.

    Deliberately mirrors the consumer corroboration scorer (`_score_consumer`):
    each independent evidence source is a "kind", the strongest kind drives the
    score, additional kinds corroborate, and a bounded log-volume term rewards a
    DOI surfaced through multiple channels. The dominant kind is discovery
    *provenance* — how the DOI was found — augmented by lexical overlap of the
    paper's content against the repo profile (authors / terms / concepts / venue).

    A bare `keyword_search`-only hit scores at most the keyword_search
    provenance weight (1) and lands in `low`; it needs real corroboration (a
    shared author, overlapping terms/concepts, or a matching venue) to clear the
    `medium` cutoff. That is the colliding-name ("zfp") false-positive guard."""

    def score(self, meta, provenance, profile):
        """Return (score, tier, evidence). `meta` carries title/abstract/authors/
        concepts/venue; `provenance` is the set of channels for this DOI;
        `profile` is the repo profile (see CitationEngine._score_paper)."""
        signals = {}
        evidence = {}

        prov_weight = max(
            (PROVENANCE_WEIGHT.get(p, 0) for p in provenance), default=0
        )
        if prov_weight:
            signals["provenance"] = float(prov_weight)
        evidence["provenance"] = sorted(provenance)

        paper_authors = {a.lower().strip() for a in meta.get("authors", []) if a}
        shared_authors = sorted(
            paper_authors & {a.lower() for a in profile.get("seminal_authors", set())}
        )
        if shared_authors:
            signals["author_overlap"] = PAPER_AUTHOR_OVERLAP_WEIGHT
            evidence["sharedAuthors"] = shared_authors

        profile_terms = profile.get("terms", set())
        if profile_terms:
            paper_tokens = set(
                _tokenize(f"{meta.get('title', '')} {meta.get('abstract', '')}")
            )
            matched_terms = sorted(paper_tokens & profile_terms)
            if matched_terms:
                fraction = len(matched_terms) / len(profile_terms)
                signals["term_overlap"] = PAPER_TERM_OVERLAP_WEIGHT * min(
                    1.0, fraction
                )
                evidence["matchedTerms"] = matched_terms

        profile_topics = {t.lower() for t in profile.get("topics", set())}
        if profile_topics:
            paper_concepts = {c.lower().strip() for c in meta.get("concepts", []) if c}
            matched_concepts = sorted(paper_concepts & profile_topics)
            if matched_concepts:
                signals["concept_overlap"] = PAPER_CONCEPT_OVERLAP_WEIGHT
                evidence["matchedConcepts"] = matched_concepts

        venue = (meta.get("venue") or meta.get("journal") or "").lower().strip()
        seminal_venues = {v.lower() for v in profile.get("seminal_venues", set())}
        if venue and venue in seminal_venues:
            signals["venue_match"] = PAPER_VENUE_MATCH_WEIGHT
            evidence["venue"] = meta.get("venue") or meta.get("journal")

        channels = len(provenance)
        evidence["channels"] = channels

        if not signals:
            return 0.0, "low", evidence

        strongest = max(signals.values())
        corroboration = (len(signals) - 1) * PAPER_CORROBORATION_BONUS
        volume = min(math.log10(channels + 1), PAPER_VOLUME_CAP)
        score = strongest + corroboration + volume
        tier = (
            "high"
            if score >= PAPER_TIER_HIGH
            else "medium"
            if score >= PAPER_TIER_MEDIUM
            else "low"
        )
        return round(score, 2), tier, evidence


class LLMRelevanceJudge:
    """Optional tie-breaker for *borderline* papers, pointed at any OpenAI-
    compatible chat endpoint (llama.cpp / LMStudio / vLLM / Ollama shim) via a
    configurable base URL + model. Off unless a URL is provided. Uses only
    `requests`; any failure degrades silently to the heuristic tier."""

    def __init__(self, base_url, model, token=None, email=None):
        self.base_url = (base_url or "").rstrip("/")
        self.model = model or "local-model"
        self.token = token
        self.email = email

    @property
    def enabled(self):
        return bool(self.base_url)

    def judge(self, profile, meta, log):
        """Return a small verdict dict {relevant, confidence, reason} or None."""
        if not self.enabled:
            return None
        prompt = (
            "You judge whether an academic paper references or uses a specific "
            "software project. Answer ONLY with compact JSON: "
            '{"relevant": true|false, "confidence": 0.0-1.0, "reason": "..."}.\n\n'
            f"PROJECT: {profile.get('name')} (owner: {profile.get('owner')})\n"
            f"PROJECT TOPICS: {', '.join(sorted(profile.get('topics', set())))}\n"
            f"PROJECT TERMS: {', '.join(sorted(list(profile.get('terms', set()))[:30]))}\n\n"
            f"PAPER TITLE: {meta.get('title', '')}\n"
            f"PAPER VENUE: {meta.get('venue') or meta.get('journal') or ''}\n"
            f"PAPER ABSTRACT: {(meta.get('abstract') or '')[:1500]}\n"
        )
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "max_tokens": 200,
        }
        try:
            resp = requests.post(
                f"{self.base_url}/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=30,
            )
            if resp.status_code != 200:
                if log:
                    log.debug(
                        "LLM judge non-200", extra={"status": resp.status_code}
                    )
                return None
            content = (
                resp.json()["choices"][0]["message"]["content"]
            )
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if not match:
                return None
            verdict = json.loads(match.group(0))
            if "relevant" not in verdict:
                return None
            return {
                "relevant": bool(verdict.get("relevant")),
                "confidence": float(verdict.get("confidence", 0.0) or 0.0),
                "reason": str(verdict.get("reason", ""))[:300],
            }
        except Exception as e:
            if log:
                log.debug("LLM judge failed", extra={"error": str(e)})
            return None


class CitationEngine:
    def __init__(self, email, args=None):
        self.joss_plugin = JOSSPublicationPlugin(email)
        self.cff_plugin = CFFPublicationPlugin(email)
        self.zenodo_plugin = ZenodoPublicationPlugin(email)
        self.text_plugin = TextMatchPublicationPlugin(email)
        self.scrape_plugin = WebScrapePublicationPlugin(email)
        self.openalex_plugin = OpenAlexPublicationPlugin(email)
        self.opencitations_plugin = OpenCitationsPlugin(email)
        self.crossref_plugin = CrossrefPublicationPlugin(email)

        self.joss_plugin.initialize()

        # Plugins that make network calls we track for completeness; their
        # `.diag` is swapped per node in get_publications.
        self._net_plugins = [
            self.openalex_plugin,
            self.opencitations_plugin,
            self.crossref_plugin,
        ]

        self.args = args
        self.scorer = PaperRelevanceScorer()
        self.relevance_enabled = not getattr(args, "no_paper_relevance", False)
        self.filter_papers = not getattr(args, "no_paper_filter", False)
        floor = getattr(args, "paper_relevance_floor", "medium") or "medium"
        self.relevance_floor = PAPER_TIER_ORDER.get(floor, 1)

        self.judge = LLMRelevanceJudge(
            getattr(args, "relevance_llm_url", None),
            getattr(args, "relevance_llm_model", None),
            token=os.environ.get("RELEVANCE_LLM_TOKEN"),
            email=email,
        )

        # DOI -> backfilled OpenAlex meta cache (persisted like the IDF cache).
        self.cache_path = getattr(args, "paper_cache", None) or None
        self.paper_cache = {}
        self._load_cache()

    def _load_cache(self):
        if self.cache_path and os.path.exists(self.cache_path):
            try:
                with open(self.cache_path) as f:
                    self.paper_cache = json.load(f)
            except Exception:
                self.paper_cache = {}

    def save(self):
        if not self.cache_path:
            return
        try:
            with open(self.cache_path, "w") as f:
                json.dump(self.paper_cache, f)
        except Exception:
            pass

    @staticmethod
    def _frontier_rank(doi_meta, doi):
        """Deterministic priority for capping the frontier: most-cited first
        (when OpenAlex citation counts are known), DOI as the stable tiebreak.
        Makes the truncated set reproducible instead of set-iteration-random,
        and — per the original TODO — also keeps the *most influential* citers
        when the cap bites."""
        cites = (doi_meta.get(doi) or {}).get("openalex_citations") or 0
        return (-cites, doi)

    def _expand_citations(
        self, seminal_dois, max_depth, doi_meta, doi_provenance, log, diag=None
    ):
        """Breadth-first crawl of the reverse-citation graph seeded by the
        seminal DOIs. Returns {doi: depth} (0 == seminal, 1 == direct citer,
        ...), and folds discovered work metadata/provenance into the passed
        `doi_meta` / `doi_provenance` accumulators. Bounded by CITATION_MAX_*."""
        depth_of = {d: 0 for d in seminal_dois}
        frontier = set(seminal_dois)
        depth = 0

        while frontier and depth < max_depth:
            depth += 1

            # Bound the fan-out deterministically: rank the frontier (most-cited
            # first, DOI tiebreak) BEFORE slicing, so which DOIs get expanded
            # when the cap bites does not depend on set-iteration order.
            ranked = sorted(
                frontier, key=lambda d: self._frontier_rank(doi_meta, d)
            )
            batch = ranked[:CITATION_MAX_PER_LEVEL]
            if len(frontier) > CITATION_MAX_PER_LEVEL:
                log.warning(
                    "Citation frontier exceeds per-level cap; truncating",
                    extra={"frontier": len(frontier), "cap": CITATION_MAX_PER_LEVEL},
                )
                if diag is not None:
                    diag.record_cap("citation_per_level")

            citing_meta = self.openalex_plugin.discover_citing(batch, log)
            for cdoi, meta in citing_meta.items():
                self._merge_meta(doi_meta, cdoi, meta)
                doi_provenance[cdoi].add("reverse_citation")

            oc_dois = self.opencitations_plugin.citing_dois(batch, log)
            for cdoi in oc_dois:
                doi_provenance[cdoi].add("reverse_citation_oc")

            citing = set(citing_meta) | oc_dois

            # Only DOIs we have never expanded before: this is the cycle guard.
            new = citing - depth_of.keys()
            for d in new:
                depth_of[d] = depth

            log.info(
                f"Citation hop {depth}: +{len(new)} DOIs ({len(depth_of)} total)"
            )

            if len(depth_of) >= CITATION_MAX_TOTAL:
                log.warning(
                    "Citation crawl hit total cap; halting expansion",
                    extra={"cap": CITATION_MAX_TOTAL},
                )
                if diag is not None:
                    diag.record_cap("citation_total")
                break

            frontier = new

        return depth_of

    @staticmethod
    def _merge_meta(doi_meta, doi, meta):
        """Union a work's parsed meta into the accumulator, preferring existing
        non-empty content but always merging provenance and concepts."""
        if not doi:
            return
        existing = doi_meta.get(doi)
        if existing is None:
            doi_meta[doi] = dict(meta)
            doi_meta[doi]["provenance"] = set(meta.get("provenance", set()))
            return
        existing["provenance"] = set(existing.get("provenance", set())) | set(
            meta.get("provenance", set())
        )
        for key in ("title", "abstract", "venue", "year", "openalex_id"):
            if not existing.get(key) and meta.get(key):
                existing[key] = meta[key]
        for key in ("authors", "concepts"):
            merged = list(
                dict.fromkeys((existing.get(key) or []) + (meta.get(key) or []))
            )
            if merged:
                existing[key] = merged
        if meta.get("openalex_citations") and not existing.get("openalex_citations"):
            existing["openalex_citations"] = meta["openalex_citations"]

    def _apply_diag(self, diag):
        for p in self._net_plugins:
            p.diag = diag

    @staticmethod
    def _paper_sort_key(p):
        """Stable, meaningful output order: most-relevant first, then by
        citation depth, then DOI. Independent of set-iteration order so two
        runs over the same data emit byte-identical paper lists."""
        return (
            -PAPER_TIER_ORDER.get(p.get("relevanceTier"), -1),
            -(p.get("relevanceScore") or 0),
            p.get("citationDepth", 0),
            p.get("doi") or "",
        )

    def get_publications(
        self, repo_url, repo_meta, target_urls, all_text, keywords, log,
        citation_depth=CITATION_DEFAULT_DEPTH, profile=None,
    ):
        diag = CitationDiagnostics()
        self._apply_diag(diag)
        try:
            papers = self._get_publications(
                repo_url, repo_meta, target_urls, all_text, keywords, log,
                citation_depth, profile, diag,
            )
        finally:
            self._apply_diag(None)  # don't leak this node's collector to the next
        if not diag.complete:
            log.warning(
                "Citation search for this node is INCOMPLETE",
                extra={"warnings": diag.warnings()},
            )
        return papers, diag.summary()

    def _get_publications(
        self, repo_url, repo_meta, target_urls, all_text, keywords, log,
        citation_depth, profile, diag,
    ):
        seminal_dois = set()
        seminal_dois.update(self.joss_plugin.discover_seminal(repo_url, repo_meta, log))
        seminal_dois.update(self.cff_plugin.discover_seminal(repo_url, repo_meta, log))
        seminal_dois.update(
            self.zenodo_plugin.discover_seminal(repo_url, repo_meta, log)
        )

        if seminal_dois:
            log.info(f"Identified {len(seminal_dois)} Seminal DOIs for reverse-lookup.")

        profile = dict(profile or {})
        profile.setdefault("terms", set())
        profile.setdefault("topics", set())
        profile.setdefault("seminal_authors", set())
        profile.setdefault("seminal_venues", set())

        # doi -> merged work meta (scoring content); doi -> set of provenances.
        doi_meta = {}
        doi_provenance = defaultdict(set)
        for d in seminal_dois:
            doi_provenance[d].add("seminal")

        # Resolve seminal DOIs FIRST so their authors/venue seed the profile
        # before any citing paper is scored (they are the strongest overlap
        # signal a citing paper can corroborate against).
        seminal_records = {}
        for doi in seminal_dois:
            rec = self.joss_plugin.joss_map.get(doi)
            if not rec:
                rec = self.crossref_plugin.resolve_doi(doi, log)
            if rec:
                seminal_records[doi] = rec
                for a in rec.get("authors", []) or []:
                    profile["seminal_authors"].add(a)
                venue = rec.get("journal") or rec.get("venue")
                if venue and venue != "Unknown":
                    profile["seminal_venues"].add(venue)
        diag.seminal_found = len(seminal_records)

        # Reverse-citation crawl, seeded only by seminal DOIs.
        depth_of = self._expand_citations(
            seminal_dois, citation_depth, doi_meta, doi_provenance, log, diag
        )

        # One-shot seed signals (text mining + full-text search) never recurse;
        # they are treated as direct evidence, folded in at depth 0.
        for d in self.text_plugin.discover_dois(all_text, log):
            doi_provenance[d].add("text_scrape")
            depth_of.setdefault(d, 0)
        for d in self.scrape_plugin.discover_dois(target_urls, log):
            doi_provenance[d].add("web_scrape")
            depth_of.setdefault(d, 0)
        for d, meta in self.openalex_plugin.seed_search(
            target_urls, keywords, log
        ).items():
            self._merge_meta(doi_meta, d, meta)
            doi_provenance[d].add("keyword_search")
            depth_of.setdefault(d, 0)

        diag.dois_seen = len(depth_of)
        papers = []
        log.debug(f"Resolving/scoring {len(depth_of)} unique DOIs")
        for doi, doi_depth in depth_of.items():
            paper = self._resolve_and_score(
                doi, doi_depth, doi_meta.get(doi), doi_provenance.get(doi, set()),
                seminal_records.get(doi), profile, log,
            )
            if paper is None:
                # No metadata at all resolved for this DOI — a gap, not a low
                # score. Recorded so the count of dropped-for-lack-of-data is
                # visible rather than silently shrinking the graph.
                diag.dois_unresolved += 1
                continue
            # Default filter: drop noise below the floor, but never a truly
            # seminal paper (the repo's own work is always retained). The
            # exemption keys on *provenance*, not the depth-0 `relation` field:
            # a bare keyword-search seed hit is also depth 0 but must remain
            # filterable — that is the colliding-name ("zfp") case.
            if (
                self.relevance_enabled
                and self.filter_papers
                and "seminal" not in doi_provenance.get(doi, set())
                and PAPER_TIER_ORDER.get(paper.get("relevanceTier"), 0)
                < self.relevance_floor
            ):
                continue
            papers.append(paper)

        papers.sort(key=self._paper_sort_key)
        return papers

    def _resolve_and_score(
        self, doi, doi_depth, meta, provenance, seminal_rec, profile, log
    ):
        """Merge OpenAlex + Crossref metadata for one DOI, score its relevance,
        and return the emitted paper dict (raw abstract dropped) or None."""
        # OpenAlex backfill when no OpenAlex channel surfaced this DOI (e.g. it
        # arrived via text/web scrape or OpenCitations) but we want its content
        # for scoring. Cached on disk across runs.
        if meta is None and self.relevance_enabled:
            if doi in self.paper_cache:
                meta = self.paper_cache[doi]
            else:
                fetched = self.openalex_plugin.fetch_by_doi(doi, log)
                if fetched is not None:
                    fetched = dict(fetched)
                    fetched["provenance"] = sorted(fetched.get("provenance", set()))
                    self.paper_cache[doi] = fetched
                meta = fetched
        meta = dict(meta) if meta else {}

        # Crossref (or JOSS map) for the emitted title/journal/citations/url.
        res = seminal_rec or self.joss_plugin.joss_map.get(doi)
        if not res:
            res = self.crossref_plugin.resolve_doi(doi, log)
        if not res and not meta:
            return None
        res = dict(res) if res else {}

        # Unify the two sources into one scoring/content view.
        content = {
            "title": res.get("title") or meta.get("title") or "",
            "abstract": meta.get("abstract") or res.get("abstract") or "",
            "authors": meta.get("authors") or res.get("authors") or [],
            "concepts": meta.get("concepts") or [],
            "venue": meta.get("venue") or res.get("journal") or "",
            "journal": res.get("journal") or meta.get("venue") or "Unknown",
            "year": res.get("year") or meta.get("year"),
        }
        if res.get("subjects"):
            content["concepts"] = list(
                dict.fromkeys(content["concepts"] + res["subjects"])
            )

        paper = {
            "title": content["title"],
            "doi": doi,
            "journal": content["journal"],
            "url": res.get("url"),
            "citations": res.get("citations", meta.get("openalex_citations", 0)),
            "citationDepth": doi_depth,
            # Historical semantics: depth 0 == seminal or a one-shot seed hit.
            "relation": "seminal" if doi_depth == 0 else "citing",
            "authors": content["authors"],
            "year": content["year"],
            "concepts": content["concepts"],
            "provenance": sorted(provenance),
        }

        if self.relevance_enabled:
            score, tier, evidence = self.scorer.score(content, provenance, profile)
            # Borderline papers (just under a tier cutoff) get the optional LLM
            # tie-breaker, if configured.
            if self.judge.enabled and self._is_borderline(score):
                verdict = self.judge.judge(profile, content, log)
                if verdict is not None:
                    evidence["llm"] = verdict
                    score, tier = self._apply_llm(score, tier, verdict)
            paper["relevanceScore"] = score
            paper["relevanceTier"] = tier
            paper["relevanceEvidence"] = evidence

        return paper

    @staticmethod
    def _is_borderline(score):
        for cutoff in (PAPER_TIER_MEDIUM, PAPER_TIER_HIGH):
            if cutoff - PAPER_LLM_BORDERLINE_MARGIN <= score < cutoff:
                return True
        return False

    @staticmethod
    def _apply_llm(score, tier, verdict):
        """Nudge score/tier by a borderline LLM verdict. A confident 'relevant'
        promotes across the nearest cutoff; a confident 'not relevant' demotes."""
        confidence = verdict.get("confidence", 0.0)
        if verdict.get("relevant") and confidence >= 0.5:
            for cutoff in (PAPER_TIER_MEDIUM, PAPER_TIER_HIGH):
                if cutoff - PAPER_LLM_BORDERLINE_MARGIN <= score < cutoff:
                    score = round(cutoff, 2)
                    break
        elif not verdict.get("relevant") and confidence >= 0.5:
            score = round(max(0.0, score - PAPER_LLM_BORDERLINE_MARGIN), 2)
        tier = (
            "high"
            if score >= PAPER_TIER_HIGH
            else "medium"
            if score >= PAPER_TIER_MEDIUM
            else "low"
        )
        return score, tier


class GitHubEnricher:
    def __init__(self, gh_token):
        self.gh_token = gh_token

    def parse_repo_info(self, repo_full_name):
        clean = (
            repo_full_name.replace("github.com/", "")
            .replace("gitlab.com/", "")
            .replace(".git", "")
        )
        parts = clean.split("/")
        return (parts[0], parts[1]) if len(parts) >= 2 else ("unknown", clean)

    def get_metadata(self, repo_full_name, log):
        if (
            not self.gh_token
            or "gitlab.com" in repo_full_name
            or "bitbucket.org" in repo_full_name
        ):
            return {}
        owner, name = self.parse_repo_info(repo_full_name)
        if owner == "unknown":
            return {}

        query = """
        query($owner: String!, $name: String!) {
          repository(owner: $owner, name: $name) {
            isFork stargazerCount description homepageUrl licenseInfo { name } updatedAt
            repositoryTopics(first: 20) { nodes { topic { name } } }
            releases(last: 1) { nodes { publishedAt } }
            defaultBranchRef { target { ... on Commit { oid history { totalCount } } } }
            mentionableUsers(first: 1) { totalCount }
            readme: object(expression: "HEAD:README.md") { ... on Blob { text } }
            cff: object(expression: "HEAD:CITATION.cff") { ... on Blob { text } }
            codemeta: object(expression: "HEAD:codemeta.json") { ... on Blob { text } }
            zenodo: object(expression: "HEAD:.zenodo.json") { ... on Blob { text } }
            zenodo_alt: object(expression: "HEAD:zenodo.json") { ... on Blob { text } }
          }
        }
        """
        log.debug("Fetching GitHub Metadata", extra={"repo": repo_full_name})
        try:
            resp = requests.post(
                "https://api.github.com/graphql",
                headers={"Authorization": f"Bearer {self.gh_token}"},
                json={"query": query, "variables": {"owner": owner, "name": name}},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("repository")
                if data:
                    return {
                        "isFork": data.get("isFork", False),
                        "stars": data.get("stargazerCount", 0),
                        "description": data.get("description", ""),
                        "homepageUrl": data.get("homepageUrl", ""),
                        "license": data.get("licenseInfo", {}).get("name", "None")
                        if data.get("licenseInfo")
                        else "None",
                        "lastUpdate": data.get("updatedAt", ""),
                        "commitSha": data.get("defaultBranchRef", {})
                        .get("target", {})
                        .get("oid", "HEAD")
                        if data.get("defaultBranchRef")
                        else "HEAD",
                        "commits": data.get("defaultBranchRef", {})
                        .get("target", {})
                        .get("history", {})
                        .get("totalCount", 0)
                        if data.get("defaultBranchRef")
                        else 0,
                        "latestRelease": data.get("releases", {})
                        .get("nodes", [{"publishedAt": ""}])[0]
                        .get("publishedAt", "")
                        if data.get("releases", {}).get("nodes")
                        else "",
                        "contributors": data.get("mentionableUsers", {}).get(
                            "totalCount", 0
                        )
                        if data.get("mentionableUsers")
                        else 0,
                        "readme": data.get("readme", {}).get("text", "")
                        if data.get("readme")
                        else "",
                        "cff": data.get("cff", {}).get("text", "")
                        if data.get("cff")
                        else "",
                        "codemeta": data.get("codemeta", {}).get("text", "")
                        if data.get("codemeta")
                        else "",
                        "zenodo": data.get("zenodo", {}).get("text", "")
                        if data.get("zenodo")
                        else "",
                        "zenodo_alt": data.get("zenodo_alt", {}).get("text", "")
                        if data.get("zenodo_alt")
                        else "",
                        "topics": [
                            n["topic"]["name"]
                            for n in (
                                data.get("repositoryTopics", {}) or {}
                            ).get("nodes", [])
                            if n.get("topic", {}).get("name")
                        ],
                    }
        except Exception as e:
            log.debug("GH API Error", extra={"error": str(e)})
        return {}


class SPDXManager:
    def __init__(self, output_dir=SNIPPETS_DIR):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_snippet(
        self,
        consumer_repo,
        provider_repo,
        consumer_sha,
        provider_sha,
        github_enricher,
        log,
    ):
        c_owner, c_name = github_enricher.parse_repo_info(consumer_repo)
        p_owner, p_name = github_enricher.parse_repo_info(provider_repo)
        c_safe, p_safe = (
            consumer_repo.replace("/", "-").replace(".", "-"),
            provider_repo.replace("/", "-").replace(".", "-"),
        )

        snippet = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{c_name} Dependency Manifest",
            "documentNamespace": f"https://github.com/{consumer_repo}/spdx/{consumer_sha}",
            "packages": [
                {
                    "name": c_name,
                    "SPDXID": f"SPDXRef-Package-{c_safe}",
                    "versionInfo": consumer_sha,
                    "downloadLocation": f"git+https://github.com/{consumer_repo}.git@{consumer_sha}",
                    "filesAnalyzed": False,
                },
                {
                    "name": p_name,
                    "SPDXID": f"SPDXRef-Package-{p_safe}",
                    "versionInfo": provider_sha,
                    "downloadLocation": f"git+https://github.com/{provider_repo}.git@{provider_sha}",
                    "filesAnalyzed": False,
                },
            ],
            "relationships": [
                {
                    "spdxElementId": f"SPDXRef-Package-{c_safe}",
                    "relatedSpdxElement": f"SPDXRef-Package-{p_safe}",
                    "relationshipType": "DEPENDS_ON",
                }
            ],
        }

        path = os.path.join(
            self.output_dir, f"{consumer_repo.replace('/', '_')}.spdx.json"
        )
        with open(path, "w") as f:
            json.dump(snippet, f, indent=2)
        return path


class IdentifierKind:
    """The distinct identities a C/C++ project exposes, any of which a consumer
    might reference. A project's name, headers, CMake package, exported targets,
    pkg-config module, library artifact, Bazel module, and repo URL are only
    loosely coupled and frequently diverge, so we compile the whole set rather
    than guessing one canonical token."""

    HEADER_PATH = "header_path"
    HEADER_BASENAME = "header_basename"
    MODULE_NAME = "module_name"
    CMAKE_PACKAGE = "cmake_package"
    CMAKE_TARGET = "cmake_target"
    PKGCONFIG = "pkgconfig"
    LIB_ARTIFACT = "lib_artifact"
    BAZEL_MODULE = "bazel_module"
    REPO_URL = "repo_url"
    REPO_SLUG = "repo_slug"
    PROJECT_NAME = "project_name"
    ALIAS = "alias"


# Base specificity/confidence contribution per identifier kind. An exact repo
# URL reference is near-certain; a bare header basename is weak. These are the
# pre-IDF weights; per-token specificity (Phase 1) scales them down further.
KIND_WEIGHTS = {
    IdentifierKind.REPO_URL: 6,
    IdentifierKind.REPO_SLUG: 6,
    IdentifierKind.CMAKE_TARGET: 5,
    IdentifierKind.CMAKE_PACKAGE: 5,
    IdentifierKind.MODULE_NAME: 4,
    IdentifierKind.BAZEL_MODULE: 4,
    IdentifierKind.PKGCONFIG: 4,
    IdentifierKind.LIB_ARTIFACT: 3,
    IdentifierKind.HEADER_PATH: 3,
    IdentifierKind.HEADER_BASENAME: 2,
    IdentifierKind.PROJECT_NAME: 1,
    IdentifierKind.ALIAS: 1,
}


# Axis-A evidence layers (see DISCOVERY_EXPANSION_NOTES.md Part 6). A dependency
# fact can be observed at increasing levels of authority: prose that mentions the
# project (narrative), source code that references it (source-consumption), a
# build manifest that declares it, a third-party package registry, a compiled
# artifact that actually links it (binary/link), or a signed bill of materials.
# The layer is orthogonal to the per-kind KIND_WEIGHTS: weights rank identifiers
# within a layer, the layer ranks *kinds of evidence* against each other.
LAYER_NARRATIVE = 1
LAYER_SOURCE = 2
LAYER_BUILD = 3
LAYER_REGISTRY = 4
LAYER_BINARY = 5
LAYER_SBOM = 6
LAYER_BIBLIOMETRIC = 7

# Which evidence layer each identifier kind is observed at. Unknown kinds default
# to LAYER_SOURCE (the historical assumption). New kinds from later phases add
# their entry here; the special "declared" kind is a package-registry assertion.
EVIDENCE_LAYER = {
    IdentifierKind.HEADER_PATH: LAYER_SOURCE,
    IdentifierKind.HEADER_BASENAME: LAYER_SOURCE,
    IdentifierKind.MODULE_NAME: LAYER_SOURCE,
    IdentifierKind.PROJECT_NAME: LAYER_SOURCE,
    IdentifierKind.ALIAS: LAYER_SOURCE,
    # A repo-URL/slug reference lives in build/VCS config (.gitmodules,
    # FetchContent, CPM), so it is a build-manifest declaration, not source.
    IdentifierKind.REPO_URL: LAYER_BUILD,
    IdentifierKind.REPO_SLUG: LAYER_BUILD,
    IdentifierKind.CMAKE_PACKAGE: LAYER_BUILD,
    IdentifierKind.CMAKE_TARGET: LAYER_BUILD,
    IdentifierKind.PKGCONFIG: LAYER_BUILD,
    IdentifierKind.BAZEL_MODULE: LAYER_BUILD,
    IdentifierKind.LIB_ARTIFACT: LAYER_BUILD,
    "declared": LAYER_REGISTRY,
}

# Additive confidence nudge applied to an edge by its strongest evidence layer,
# on top of the KIND_WEIGHTS sum. Source/build/registry stay at 0 so existing
# calibration is unchanged (KIND_WEIGHTS already orders them); narrative-only is
# penalised (and hard-capped at low, below), while a binary-link or SBOM edge —
# a real link / declared bill of materials, not an inferred reference — is lifted
# toward the high tier even when seen alone.
LAYER_WEIGHT = {
    LAYER_NARRATIVE: -2.0,
    LAYER_SOURCE: 0.0,
    LAYER_BUILD: 0.0,
    LAYER_REGISTRY: 0.0,
    LAYER_BINARY: 1.5,
    LAYER_SBOM: 1.5,
    LAYER_BIBLIOMETRIC: 0.0,
}


@dataclass
class Identifier:
    """One identity the provider exposes, with where it was learned from and a
    specificity multiplier (1.0 until IDF weighting fills it in)."""

    value: str
    kind: str
    provenance: str
    base_weight: int = 1
    specificity: float = 1.0

    @property
    def weight(self):
        return self.base_weight * self.specificity


@dataclass
class ConsumptionPattern:
    """A consumer-side regex derived from an Identifier, tagged with the evidence
    type recorded when it matches."""

    identifier: Identifier
    regex: str
    evidence: str
    weight: float


class IdentifierSet:
    """A deduplicated collection of Identifiers compiled for one provider node.
    Deduplication is by (kind, value) so the same string can legitimately appear
    as, e.g., both a CMake package and a pkg-config module."""

    def __init__(self, identifiers=None):
        self._by_key = {}
        for idf in identifiers or []:
            self.add(idf)

    def add(self, idf):
        self._by_key.setdefault((idf.kind, idf.value), idf)

    def __iter__(self):
        return iter(self._by_key.values())

    def __len__(self):
        return len(self._by_key)

    def of_kind(self, *kinds):
        return [i for i in self if i.kind in kinds]


# Package registries that declare dependency edges we can mine (via Sourcegraph
# searches of the registry's own repo). These are corroboration / recall / alias
# inputs reconciled on repo URL — never treated as ground truth. Adding a
# registry is data: give it the repo, a manifest file filter, a `{alias}`-
# templated "depends on X" regex, the path index of the package name, and a
# regex that pulls the packaged project's GitHub slug out of a manifest.
DECLARED_REGISTRIES = {
    "spack": {
        "repo": "github.com/spack/spack",
        "manifest": r"package\.py$",
        "depends_tmpl": r"depends_on\(\s*[\x22']{alias}[\s@\x22'+~)]",
        "name_index": -2,  # .../packages/<name>/package.py
        "url_re": r"github\.com[:/]([\w.\-]+/[\w.\-]+?)(?:\.git|[\x22'/\s)]|$)",
    },
}


class SpecificityService:
    """IDF-style guard that down-weights and drops non-discriminating identifier
    tokens by their global frequency in the code index.

    It is applied ONLY to low-context tokens (bare header basenames, generic
    single-word namespaces, bare project names). Build-system declarations
    (`find_package`, pkg-config), exported targets, and repo-URL references are
    specific *by context* and are never frequency-gated — otherwise a popular
    provider's own `find_package(GTest)` would be penalized precisely because it
    is popular. High frequency for a bare basename like `config.h` means "cannot
    attribute usage"; high frequency for `find_package(GTest)` means "many real
    dependents". Only the former is gated.

    Frequency is measured with a bounded probe (a search capped at `probe_cap`
    results); a token that saturates the cap is treated as non-discriminating.
    Results cache in-run and on disk, since token frequency is global."""

    def __init__(self, probe, enabled=True, probe_cap=300, cache_path=None):
        self._probe = probe  # callable(regex, log) -> int (count, capped)
        self.enabled = enabled
        self.probe_cap = max(1, probe_cap)
        self.cache_path = cache_path or None
        self.cache = {}
        self._load()

    def _load(self):
        if self.cache_path and os.path.exists(self.cache_path):
            try:
                with open(self.cache_path) as f:
                    self.cache = json.load(f)
            except Exception:
                self.cache = {}

    def save(self):
        if not self.cache_path:
            return
        try:
            with open(self.cache_path, "w") as f:
                json.dump(self.cache, f)
        except Exception:
            pass

    def _frequency(self, regex, log):
        if regex in self.cache:
            return self.cache[regex]
        count = self._probe(regex, log)
        self.cache[regex] = count
        return count

    def specificity(self, regex, log=None):
        """Multiplier in [0, 1]; 0 means the token is too common to search."""
        if not self.enabled:
            return 1.0
        count = self._frequency(regex, log)
        if count >= self.probe_cap:
            return 0.0
        return 1.0 - (count / self.probe_cap)


class EcosystemPlugin:
    def __init__(self, args):
        self.args = args

    def discover_dependents(self, curr_id, curr_name, curr_sha, log):
        raise NotImplementedError()


class CppSourcegraphPlugin(EcosystemPlugin):
    # Substrings that mark a GraphQL error as transient and worth retrying.
    # Sourcegraph surfaces its internal rate limiting and query timeouts here,
    # frequently riding on an HTTP 200 response.
    RETRYABLE_ERROR_HINTS = (
        "rate limit",
        "too many requests",
        "timed out",
        "timeout",
        "try again",
        "temporarily",
        "unavailable",
    )

    @staticmethod
    def _retry_after(resp, default):
        """Honor a Retry-After header (seconds) when Sourcegraph sends one."""
        ra = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
        if ra:
            try:
                return max(int(float(ra)), 1)
            except ValueError:
                pass
        return default

    def _graphql_query(self, query, variables, log, timeout=60, max_attempts=6):
        headers = {
            "Authorization": f"token {self.args.sg_token}",
            "Content-Type": "application/json",
        }
        log.debug("Executing Sourcegraph Query", extra={"variables": variables})

        backoff = 5
        for attempt in range(1, max_attempts + 1):
            try:
                resp = requests.post(
                    SOURCEGRAPH_URL,
                    headers=headers,
                    json={"query": query, "variables": variables},
                    timeout=timeout,
                )
            except requests.exceptions.RequestException as e:
                log.debug(
                    "Sourcegraph request failed",
                    extra={"attempt": attempt, "error": str(e)},
                )
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue

            # HTTP-level rate limiting / transient server errors.
            if resp.status_code == 429 or resp.status_code >= 500:
                wait = self._retry_after(resp, backoff)
                log.info(
                    f"Sourcegraph HTTP {resp.status_code}; backing off {wait}s",
                    extra={"attempt": attempt, "max_attempts": max_attempts},
                )
                time.sleep(wait)
                backoff = min(backoff * 2, 120)
                continue

            if resp.status_code != 200:
                log.debug(
                    "Sourcegraph unexpected status",
                    extra={"status": resp.status_code, "body": resp.text[:300]},
                )
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue

            try:
                payload = resp.json()
            except ValueError:
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue

            # Sourcegraph often returns HTTP 200 with a top-level `errors` array
            # (internal rate limits, query timeouts). Treating that as success is
            # what silently truncates a crawl, so inspect it explicitly.
            errors = payload.get("errors")
            if errors:
                msg = "; ".join(e.get("message", "") for e in errors)
                if any(hint in msg.lower() for hint in self.RETRYABLE_ERROR_HINTS):
                    log.info(
                        f"Sourcegraph transient GraphQL error; backing off {backoff}s",
                        extra={"attempt": attempt, "error": msg[:200]},
                    )
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 120)
                    continue
                log.debug(
                    "Sourcegraph non-retryable GraphQL error",
                    extra={"error": msg[:300]},
                )
                # Non-retryable errors may still carry partial `data`; return it.
            return payload

        log.info(
            "Sourcegraph query abandoned after exhausting retries; "
            "results for this node may be incomplete."
        )
        return None

    # Identifier kinds whose tokens are ambiguous out of context and therefore
    # subject to IDF frequency gating. Build-system / target / repo-URL kinds are
    # specific by context and are never gated (see SpecificityService).
    GATED_KINDS = {
        IdentifierKind.HEADER_BASENAME,
        IdentifierKind.HEADER_PATH,
        IdentifierKind.PROJECT_NAME,
    }

    HEADER_KINDS = {IdentifierKind.HEADER_PATH, IdentifierKind.HEADER_BASENAME}

    # Corroboration scoring. Confidence is driven by the single strongest matched
    # identifier's weight, plus a bonus for each additional *independent* kind
    # that corroborates it (a header AND a find_package AND a target is far
    # stronger than three headers), plus a small log-scaled volume term.
    CORROBORATION_BONUS = 1.5
    VOLUME_CAP = 2.0
    TIER_HIGH = 5.5
    TIER_MEDIUM = 3.0

    # Copy/rehost detection: a genuine consumer references a few of the
    # provider's headers; a bundled copy or rehost contains most of them.
    COPY_HEADER_FRACTION = 0.5
    COPY_MIN_HEADERS = 5

    # A declared dependency (found in a package registry) contributes a strong,
    # ungated corroboration signal, treated as just another matched "kind".
    DECLARED_WEIGHT = 5.0
    DECLARED_CAP = 150  # bound registry dependent resolution per node

    def __init__(self, args):
        super().__init__(args)
        self.specificity = SpecificityService(
            probe=self._probe_frequency,
            enabled=not getattr(args, "no_idf", False),
            probe_cap=getattr(args, "idf_cap", 300),
            cache_path=getattr(args, "idf_cache", None),
        )
        # Run-level discovery completeness: set when Sourcegraph truncates,
        # errors, or a stream is abandoned/interrupted. Accumulates across the
        # whole crawl; the orchestrator folds it into meta.completeness so a
        # partial dependent search is visible, not silently smaller.
        self.search_incomplete = False
        self.search_warnings = []

    def _note_search_incomplete(self, reason, log):
        self.search_incomplete = True
        if reason not in self.search_warnings:
            self.search_warnings.append(reason)

    def _probe_frequency(self, regex, log):
        """Bounded global match count for a pattern, used as an IDF proxy."""
        cap = self.specificity.probe_cap
        query = (
            f"context:global patternType:regexp {self._regexp_literal(regex)} "
            f"fork:no count:{cap} timeout:1m"
        )
        seen = 0
        for match in self._stream_search(query, log):
            if match.get("type") == "content":
                seen += 1
                if seen >= cap:
                    break
        return seen

    # Path segments that indicate a vendored/bundled copy of a library rather
    # than a genuine external dependency. Matches inside these are excluded by
    # default (see --include-vendored).
    VENDOR_DIRS = [
        "third_party",
        "thirdparty",
        "vendor",
        "vendored",
        "external",
        "extern",
        "deps",
        "_deps",
        "subprojects",
        "submodules",
    ]

    # Header discovery no longer assumes a root include/ dir — many major C++
    # projects don't have one (protobuf ships src/google/protobuf, abseil ships
    # absl/, googletest ships googletest/include/gtest). We enumerate headers
    # wherever they live and normalize each to its consumer-facing include path.
    HEADER_EXT_RE = r"\.(h|hh|hpp|hxx|ipp|inl|tcc)$"
    # CMake config-package templates and pkg-config files, whose *names* encode
    # the find_package() / pkg_check_modules() identifiers.
    BUILD_FILE_RE = r"([Cc]onfig\.cmake(\.in)?|\.pc(\.in)?)$"
    INCLUDE_ROOT_MARKERS = ("include", "inc")
    SRC_MARKERS = ("src", "source")
    NAMESPACE_CAP = 60
    BASENAME_CAP = 25
    # C++20 module interface unit extensions, and module names never worth
    # searching (the standard library). A partition (`X:part`) is reduced to its
    # primary module `X`, the only thing external consumers `import`.
    MODULE_EXT_RE = r"\.(ixx|cppm|mpp|ccm|cxx)$"
    MODULE_STOPLIST = frozenset({"std", "std.compat"})
    MODULE_CAP = 40
    BUILD_ID_CAP = 40

    def _search_paths(self, search_id, file_filter, log, cap=1000):
        """Enumerate repo-relative file paths matching a file filter via a
        scoped Sourcegraph path search."""
        query = (
            f"repo:^{re.escape(search_id)}$ type:path "
            f"file:{file_filter} count:{cap} timeout:1m"
        )
        paths = []
        for match in self._stream_search(query, log):
            path = match.get("path")
            if path:
                paths.append(path)
                if len(paths) >= cap:
                    break
        return paths

    def _discover_header_paths(self, search_id, log):
        return self._search_paths(search_id, self.HEADER_EXT_RE, log, cap=1000)

    def _discover_build_paths(self, search_id, log):
        return self._search_paths(search_id, self.BUILD_FILE_RE, log, cap=200)

    @classmethod
    def _include_path(cls, repo_path):
        """Map a repo-relative header path to the path a consumer would #include.

        The include root is whatever directory is added to the compiler's search
        path; by overwhelming convention that is the last `include/`|`inc/`
        segment, else a leading `src/`. Everything below it is namespace-invariant
        across consumers regardless of their -I flags."""
        parts = repo_path.split("/")
        lower = [p.lower() for p in parts]
        marker_idx = -1
        for i in range(len(parts) - 1):  # never treat the filename as a marker
            if lower[i] in cls.INCLUDE_ROOT_MARKERS:
                marker_idx = i
        if marker_idx >= 0:
            return "/".join(parts[marker_idx + 1 :])
        if len(parts) > 1 and lower[0] in cls.SRC_MARKERS:
            return "/".join(parts[1:])
        return repo_path

    def _extract_header_identifiers(self, search_id, curr_name, log):
        """Derive namespace (directory) and basename identifiers from the
        provider's actual headers, bounded and deduplicated. Falls back to
        conventional <name>.h / <name>/ tokens when nothing is found."""
        paths = self._discover_header_paths(search_id, log)
        if not paths:
            log.debug("No headers discovered; using convention fallback.")
            return [
                Identifier(
                    f"{curr_name}.h",
                    IdentifierKind.HEADER_BASENAME,
                    "convention_fallback",
                    KIND_WEIGHTS[IdentifierKind.HEADER_BASENAME],
                ),
                Identifier(
                    curr_name,
                    IdentifierKind.HEADER_PATH,
                    "convention_fallback",
                    KIND_WEIGHTS[IdentifierKind.HEADER_PATH],
                ),
            ]

        namespaces, basenames = {}, {}
        for repo_path in paths:
            parts = self._include_path(repo_path).split("/")
            if len(parts) >= 2:  # has a namespace directory
                namespaces.setdefault("/".join(parts[:-1]), None)
            if len(parts) <= 2:  # shallow header -> its bare basename is useful
                basenames.setdefault(parts[-1], None)

        ids = []
        for ns in sorted(namespaces)[: self.NAMESPACE_CAP]:
            ids.append(
                Identifier(
                    ns,
                    IdentifierKind.HEADER_PATH,
                    "header_search",
                    KIND_WEIGHTS[IdentifierKind.HEADER_PATH],
                )
            )
        for base in sorted(basenames)[: self.BASENAME_CAP]:
            ids.append(
                Identifier(
                    base,
                    IdentifierKind.HEADER_BASENAME,
                    "header_search",
                    KIND_WEIGHTS[IdentifierKind.HEADER_BASENAME],
                )
            )
        log.debug(
            "Header identifiers extracted",
            extra={
                "headers": len(paths),
                "namespaces": len(namespaces),
                "basenames": len(basenames),
            },
        )
        return ids

    def _fetch_build_blobs(self, search_id, log):
        """Fetch the provider's root CMakeLists.txt and MODULE.bazel in one
        Sourcegraph query (aliased blobs)."""
        q = """query($repo: String!) { repository(name: $repo) { commit(rev: "HEAD") { cmake: blob(path: "CMakeLists.txt") { content } bazel: blob(path: "MODULE.bazel") { content } } } }"""
        data = self._graphql_query(q, {"repo": search_id}, log)
        out = {"cmake": "", "bazel": ""}
        if data and isinstance(data.get("data"), dict):
            repo = data["data"].get("repository")
            commit = repo.get("commit") if isinstance(repo, dict) else None
            if isinstance(commit, dict):
                for key in out:
                    blob = commit.get(key)
                    if isinstance(blob, dict) and blob.get("content"):
                        out[key] = blob["content"]
        return out

    @staticmethod
    def _cmake_package_from_filename(base):
        """`zfpConfig.cmake.in` -> `zfp`, `Foo-config.cmake` -> `Foo`."""
        b = base[:-3] if base.endswith(".in") else base
        if not b.lower().endswith("config.cmake"):
            return None
        b = b[: -len(".cmake")]
        b = re.sub(r"[-_]?[Cc]onfig$", "", b)
        return b or None

    @staticmethod
    def _pkgconfig_from_filename(base):
        """`libzfp.pc.in` -> `libzfp`."""
        b = base[:-3] if base.endswith(".in") else base
        if b.endswith(".pc"):
            return b[: -len(".pc")] or None
        return None

    def _parse_cmake(self, text):
        """Extract package / target / library-artifact identifiers from a
        CMakeLists.txt (regex, not full CMake evaluation)."""
        ids = []
        for m in re.finditer(r"project\s*\(\s*([A-Za-z0-9_][\w.\-]*)", text):
            ids.append(
                Identifier(
                    m.group(1),
                    IdentifierKind.CMAKE_PACKAGE,
                    "cmake_project",
                    KIND_WEIGHTS[IdentifierKind.CMAKE_PACKAGE],
                )
            )
        for m in re.finditer(
            r"add_library\s*\(\s*([A-Za-z0-9_]+::[A-Za-z0-9_]+)\s+ALIAS", text
        ):
            ids.append(
                Identifier(
                    m.group(1),
                    IdentifierKind.CMAKE_TARGET,
                    "cmake_alias",
                    KIND_WEIGHTS[IdentifierKind.CMAKE_TARGET],
                )
            )
        for m in re.finditer(r"NAMESPACE\s+([A-Za-z0-9_]+)::", text):
            ids.append(
                Identifier(
                    f"{m.group(1)}::",
                    IdentifierKind.CMAKE_TARGET,
                    "cmake_namespace",
                    KIND_WEIGHTS[IdentifierKind.CMAKE_TARGET],
                )
            )
        for m in re.finditer(
            r"add_library\s*\(\s*([A-Za-z0-9_]+)\s+"
            r"(?:STATIC|SHARED|MODULE|OBJECT|INTERFACE|UNKNOWN)",
            text,
        ):
            ids.append(
                Identifier(
                    m.group(1),
                    IdentifierKind.LIB_ARTIFACT,
                    "cmake_add_library",
                    KIND_WEIGHTS[IdentifierKind.LIB_ARTIFACT],
                )
            )
        return ids

    def _parse_bazel(self, text):
        """Extract the Bazel module name from MODULE.bazel."""
        m = re.search(
            r"module\s*\(\s*[^)]*?name\s*=\s*[\x22']([^\x22']+)[\x22']", text
        )
        if m:
            return [
                Identifier(
                    m.group(1),
                    IdentifierKind.BAZEL_MODULE,
                    "bazel_module",
                    KIND_WEIGHTS[IdentifierKind.BAZEL_MODULE],
                )
            ]
        return []

    def _extract_build_identifiers(self, search_id, log):
        """Real package / target / module identifiers from the provider's build
        files: CMake config + pkg-config file *names*, plus CMakeLists.txt and
        MODULE.bazel *content*."""
        ids = []
        for path in self._discover_build_paths(search_id, log):
            base = path.rsplit("/", 1)[-1]
            pkg = self._cmake_package_from_filename(base)
            if pkg:
                ids.append(
                    Identifier(
                        pkg,
                        IdentifierKind.CMAKE_PACKAGE,
                        "cmake_config",
                        KIND_WEIGHTS[IdentifierKind.CMAKE_PACKAGE],
                    )
                )
            pc = self._pkgconfig_from_filename(base)
            if pc:
                ids.append(
                    Identifier(
                        pc,
                        IdentifierKind.PKGCONFIG,
                        "pc_file",
                        KIND_WEIGHTS[IdentifierKind.PKGCONFIG],
                    )
                )

        blobs = self._fetch_build_blobs(search_id, log)
        ids += self._parse_cmake(blobs.get("cmake") or "")
        ids += self._parse_bazel(blobs.get("bazel") or "")
        return ids[: self.BUILD_ID_CAP]

    _MODULE_DECL_RE = re.compile(r"export\s+module\s+([A-Za-z_]\w*(?:\.\w+)*)")

    def _extract_module_identifiers(self, search_id, log):
        """C++20 named-module interfaces the provider declares (`export module
        X;`), searched in consumers as `import X;`. Named-module consumption
        emits no #include, so it is invisible to header-based discovery."""
        # NB: keep the raw regex out of the f-string expression — a backslash in
        # an f-string replacement field is a syntax error before Python 3.12.
        decl_literal = self._regexp_literal(r"^\s*export\s+module\s+[A-Za-z_]")
        query = (
            f"repo:^{re.escape(search_id)}$ patternType:regexp "
            f"{decl_literal} count:200 timeout:1m"
        )
        ids, seen = [], set()
        for match in self._stream_search(query, log):
            if match.get("type") != "content":
                continue
            for line in self._match_lines(match):
                m = self._MODULE_DECL_RE.search(line)
                if not m:
                    continue
                # A partition (`X:part`) reduces to its primary module `X`; the
                # capture already stops at `:`, so this is the whole name.
                name = m.group(1)
                if name in self.MODULE_STOPLIST or name in seen:
                    continue
                seen.add(name)
                ids.append(
                    Identifier(
                        name,
                        IdentifierKind.MODULE_NAME,
                        "module_unit",
                        KIND_WEIGHTS[IdentifierKind.MODULE_NAME],
                    )
                )
                if len(ids) >= self.MODULE_CAP:
                    return ids
        return ids

    @staticmethod
    def _ci_regex(name):
        """Case-insensitive character-class form of a token. Sourcegraph's RE2 is
        case-sensitive by default, and CMake/pkg-config names are matched
        case-insensitively (e.g. find_package(ZFP) vs find_package(zfp))."""
        safe = name.replace(".", "\\.")
        return "".join(
            f"[{c.lower()}{c.upper()}]" if c.isalpha() else c for c in safe
        )

    # --- declared-dependent registries (opt-in via --declared-sources) ------

    def _enabled_registries(self):
        requested = [
            s.strip()
            for s in (self.args.declared_sources or "").split(",")
            if s.strip()
        ]
        return [s for s in requested if s in DECLARED_REGISTRIES]

    def _registry_manifest_paths(self, cfg, content_re, log, cap):
        """Paths of registry manifests whose content matches a regex."""
        query = (
            f"repo:^{re.escape(cfg['repo'])}$ patternType:regexp "
            f"{self._regexp_literal(content_re)} "
            f"file:{cfg['manifest']} count:{cap} timeout:1m"
        )
        paths = set()
        for match in self._stream_search(query, log):
            if match.get("type") == "content" and match.get("path"):
                paths.add(match["path"])
        return paths

    def _fetch_blobs(self, repo, paths, log, batch=20):
        """Fetch many blobs from one repo via batched aliased GraphQL queries."""
        out = {}
        paths = list(paths)
        for start in range(0, len(paths), batch):
            chunk = paths[start : start + batch]
            fields = " ".join(
                f"f{i}: blob(path: {json.dumps(p)}) {{ content }}"
                for i, p in enumerate(chunk)
            )
            q = f'query($repo: String!) {{ repository(name: $repo) {{ commit(rev: "HEAD") {{ {fields} }} }} }}'
            data = self._graphql_query(q, {"repo": repo}, log)
            commit = None
            if data and isinstance(data.get("data"), dict):
                r = data["data"].get("repository")
                commit = r.get("commit") if isinstance(r, dict) else None
            if not isinstance(commit, dict):
                continue
            for i, p in enumerate(chunk):
                blob = commit.get(f"f{i}")
                if isinstance(blob, dict) and blob.get("content"):
                    out[p] = blob["content"]
        return out

    def _resolve_declared_aliases(self, curr_id, log):
        """Registry package name(s) for the provider, found by locating the
        registry manifest that references the provider's GitHub slug."""
        slug = curr_id.replace("github.com/", "").strip("/")
        aliases = {}
        for source in self._enabled_registries():
            cfg = DECLARED_REGISTRIES[source]
            content_re = re.escape(f"github.com/{slug}")
            paths = self._registry_manifest_paths(cfg, content_re, log, cap=20)
            for p in paths:
                parts = p.split("/")
                try:
                    name = parts[cfg["name_index"]]
                except IndexError:
                    continue
                aliases.setdefault(source, set()).add(name)
            if source in aliases:
                log.debug(
                    "Resolved registry alias",
                    extra={"source": source, "names": sorted(aliases[source])},
                )
        return aliases

    def _find_declared_dependents(self, aliases, log):
        """Declared dependents across enabled registries, reconciled to GitHub
        slugs. Returns [{name(slug), url, source}]."""
        records = []
        for source, names in aliases.items():
            cfg = DECLARED_REGISTRIES[source]
            dep_paths = set()
            for alias in names:
                content_re = cfg["depends_tmpl"].format(alias=re.escape(alias))
                dep_paths |= self._registry_manifest_paths(
                    cfg, content_re, log, cap=self.DECLARED_CAP
                )
            blobs = self._fetch_blobs(cfg["repo"], list(dep_paths)[: self.DECLARED_CAP], log)
            for content in blobs.values():
                m = re.search(cfg["url_re"], content or "")
                if not m:
                    continue
                dep_slug = m.group(1).removesuffix(".git")
                records.append(
                    {
                        "name": dep_slug,
                        "url": f"https://github.com/{dep_slug}",
                        "source": source,
                    }
                )
        log.info(f"Declared registries contributed {len(records)} dependents.")
        return records

    def _merge_declared_dependents(self, consumers, aliases, log):
        """Fold declared dependents into the consumer set: corroborate those
        already found via source with a strong 'declared' signal, and inject the
        rest as declared-only consumers."""
        for rec in self._find_declared_dependents(aliases, log):
            rn = f"github.com/{rec['name']}"
            entry = consumers.get(rn)
            if entry is None:
                entry = consumers[rn] = {
                    "name": rn,
                    "url": rec["url"],
                    "oid": "HEAD",
                    "evidence": {},
                    "identifiers": set(),
                    "kindWeights": {},
                    "matchedHeaders": set(),
                    "provenance": set(),
                    "matchCount": 0,
                }
            entry["kindWeights"]["declared"] = max(
                entry["kindWeights"].get("declared", 0.0), self.DECLARED_WEIGHT
            )
            entry["evidence"]["declared"] = entry["evidence"].get("declared", 0) + 1
            entry["provenance"].add(f"declared:{rec['source']}")

    def _compile_identifier_set(self, curr_id, curr_name, log, declared_aliases=None):
        """Compile the provider's identifier set for one node.

        Combines repo-wide header extraction (namespace + basename identifiers),
        convention-based library/CMake/pkg-config names from the project name,
        real CMake/Bazel/pkg-config identifiers from build files, repo-URL
        identity, registry aliases, and an optional custom string."""
        search_id = curr_id if "github.com/" in curr_id else f"github.com/{curr_id}"
        idset = IdentifierSet()

        if not self.args.no_defaults:
            for idf in self._extract_header_identifiers(search_id, curr_name, log):
                idset.add(idf)

            for kind in (
                IdentifierKind.LIB_ARTIFACT,
                IdentifierKind.CMAKE_PACKAGE,
                IdentifierKind.PKGCONFIG,
            ):
                idset.add(
                    Identifier(curr_name, kind, "convention", KIND_WEIGHTS[kind])
                )

            for idf in self._extract_build_identifiers(search_id, log):
                idset.add(idf)

            for idf in self._extract_module_identifiers(search_id, log):
                idset.add(idf)

            for idf in self._extract_vcs_identifiers(curr_id):
                idset.add(idf)

            # Registry names for the provider (Spack etc.) are searched as
            # find_package / pkg-config identifiers — a low-noise use of aliases
            # that also handles registry renaming (e.g. Spack's py- prefix).
            for source, names in (declared_aliases or {}).items():
                for name in names:
                    for kind in (
                        IdentifierKind.CMAKE_PACKAGE,
                        IdentifierKind.PKGCONFIG,
                    ):
                        idset.add(
                            Identifier(
                                name, kind, f"declared:{source}", KIND_WEIGHTS[kind]
                            )
                        )

        if self.args.custom_string:
            idset.add(
                Identifier(
                    self.args.custom_string,
                    IdentifierKind.ALIAS,
                    "custom",
                    KIND_WEIGHTS[IdentifierKind.ALIAS],
                )
            )
        return idset

    def _patterns_for_identifier(self, idf):
        """Consumer-side (regex, evidence) pairs an identifier is searched by.
        Phase 0 mirrors the original patterns and evidence labels verbatim."""
        k = idf.kind
        if k == IdentifierKind.HEADER_PATH:
            safe = re.escape(idf.value)
            bracket = f"[<\\x22]{safe}/.*[>\\x22]"
            # Also match a C++20 header-unit import of the same header
            # (`import <foo/bar.h>;`), which #include-only search misses.
            return [
                (f"include\\s*{bracket}", "include"),
                (f"import\\s+{bracket}\\s*;", "header_unit"),
            ]
        if k == IdentifierKind.HEADER_BASENAME:
            safe = re.escape(idf.value)
            # Namespace-invariant: the basename is stable across consumers even
            # when the include-path prefix varies with their -I flags. The
            # optional prefix must end at a path boundary so `zfp.h` does not
            # match `libzfp.h`.
            bracket = f"[<\\x22](?:[^<>\\x22]*/)?{safe}[>\\x22]"
            return [
                (f"include\\s*{bracket}", "include"),
                (f"import\\s+{bracket}\\s*;", "header_unit"),
            ]
        if k == IdentifierKind.MODULE_NAME:
            # `import fmt;` / `export import boost.json;` — a named-module import,
            # distinct from a header-unit import (which carries <>/"").
            n = re.escape(idf.value)
            return [(f"^\\s*(?:export\\s+)?import\\s+{n}\\s*;", "import")]
        if k == IdentifierKind.LIB_ARTIFACT:
            return [
                (
                    f"pragma\\s+comment\\s*\\(\\s*lib\\s*,\\s*\\x22.*{idf.value}.*\\x22\\s*\\)",
                    "pragma_lib",
                )
            ]
        if k == IdentifierKind.CMAKE_PACKAGE:
            return [
                (
                    f"find_package\\s*\\(\\s*{self._ci_regex(idf.value)}[\\s)]",
                    "find_package",
                )
            ]
        if k == IdentifierKind.PKGCONFIG:
            return [
                (
                    f"pkg_check_modules\\s*\\([^)]*\\b{self._ci_regex(idf.value)}\\b",
                    "pkg_config",
                )
            ]
        if k == IdentifierKind.CMAKE_TARGET:
            if idf.value.endswith("::"):
                ns = re.escape(idf.value[:-2])
                return [(f"\\b{ns}::[A-Za-z0-9_]", "cmake_target")]
            return [(f"\\b{re.escape(idf.value)}\\b", "cmake_target")]
        if k == IdentifierKind.BAZEL_MODULE:
            n = re.escape(idf.value)
            return [
                (f"bazel_dep\\s*\\([^)]*name\\s*=\\s*[\\x22']{n}[\\x22']", "bazel"),
                (f"@{n}//", "bazel"),
            ]
        if k == IdentifierKind.REPO_SLUG:
            owner, repo = idf.value.split("/", 1)
            o, r = re.escape(owner), re.escape(repo)
            # .gitmodules / FetchContent GIT_REPOSITORY / ExternalProject URL,
            # and CPM's gh: shorthand. All reference the repo by identity, so no
            # name-mapping guess is involved.
            return [
                (f"github\\.com[:/]{o}/{r}(\\.git|/|\\b)", "vcs_ref"),
                (f"[\\x22']gh:{o}/{r}[@\\x22'/]", "vcs_ref"),
            ]
        if k == IdentifierKind.ALIAS:
            return [(idf.value, "custom")]
        return []

    def _extract_vcs_identifiers(self, curr_id):
        """The repo slug is the one unambiguous identity — search for direct
        references to it (submodules, FetchContent, CPM)."""
        slug = curr_id.replace("github.com/", "").strip("/")
        parts = slug.split("/")
        if len(parts) < 2:
            return []
        return [
            Identifier(
                f"{parts[0]}/{parts[1]}",
                IdentifierKind.REPO_SLUG,
                "vcs",
                KIND_WEIGHTS[IdentifierKind.REPO_SLUG],
            )
        ]

    def _is_gated(self, idf, protected_stems):
        """Whether an identifier is subject to IDF frequency gating.

        Only low-context tokens are gated. A multi-component namespace path
        (absl/strings, google/protobuf) is specific by structure and exempt. A
        single-component namespace or basename whose stem is the provider's own
        name (gtest -> gtest.h, zfp -> zfp/) is exempt too, so a popular
        provider's own distinctive token is not dropped merely for being
        popular; generic words (utils/, config.h) remain gated."""
        if idf.kind not in self.GATED_KINDS:
            return False
        if idf.kind == IdentifierKind.HEADER_PATH and "/" in idf.value:
            return False
        stem = idf.value.rsplit("/", 1)[-1].split(".", 1)[0].lower()
        if stem in protected_stems:
            return False
        return True

    def _patterns_from(self, idset, log=None, protected_stems=frozenset()):
        """Flatten an IdentifierSet into ConsumptionPatterns, applying IDF
        specificity gating to the ambiguous (low-context) identifier kinds. A
        gated token whose specificity collapses to 0 (too common to attribute)
        is dropped from the search entirely; others are weight-scaled."""
        patterns = []
        for idf in idset:
            gated = self._is_gated(idf, protected_stems)
            for regex, evidence in self._patterns_for_identifier(idf):
                weight = idf.base_weight
                if gated:
                    spec = self.specificity.specificity(regex, log)
                    if spec <= 0:
                        if log:
                            log.debug(
                                "Dropping non-discriminating identifier",
                                extra={"identifier": idf.value, "kind": idf.kind},
                            )
                        continue
                    idf.specificity = spec
                    weight = idf.base_weight * spec
                patterns.append(ConsumptionPattern(idf, regex, evidence, weight))
        return patterns

    def _classify(self, preview, compiled_patterns):
        """Return the ConsumptionPatterns whose regex matches a given line."""
        return [p for p, rx in compiled_patterns if rx.search(preview)]

    DOC_PATH_RE = re.compile(r"(^|/)docs?/|\.(md|rst|adoc)$", re.IGNORECASE)

    def _is_doc_path(self, path):
        """Whether a file path is documentation (weaker usage evidence). Note
        CMakeLists.txt is intentionally not matched (it is real build config)."""
        return bool(self.DOC_PATH_RE.search(path or ""))

    @staticmethod
    def _evidence_layers(kind_weights):
        """The distinct Axis-A evidence layers present in a match set, sorted.
        Unknown kinds default to LAYER_SOURCE (the historical assumption)."""
        return sorted(
            {EVIDENCE_LAYER.get(kind, LAYER_SOURCE) for kind in kind_weights}
        )

    def _score_consumer(self, kind_weights, match_count):
        """Corroboration score + tier from the per-kind best pattern weights.

        Driven by the strongest single signal, plus cross-layer corroboration,
        plus a bounded volume term, plus an evidence-layer nudge. Weights already
        reflect IDF specificity, so a lone generic-basename match scores low while
        an exact-identity vcs_ref or a corroborated find_package scores high.

        Corroboration accrues per distinct *evidence layer*, not per kind: two
        header signals (both source-consumption) are one corroboration unit,
        while a header plus a find_package (source + build-manifest) are two.
        Cross-reach agreement on the same fact therefore does not inflate
        confidence; independent cross-layer evidence does."""
        if not kind_weights:
            return 0.0, "unknown"
        layers = self._evidence_layers(kind_weights)
        top_layer = layers[-1]
        strongest = max(kind_weights.values())
        corroboration = (len(layers) - 1) * self.CORROBORATION_BONUS
        volume = min(math.log10(match_count + 1), self.VOLUME_CAP)
        score = strongest + corroboration + volume + LAYER_WEIGHT.get(top_layer, 0.0)
        # Narrative-only evidence (docs/prose) never clears low on its own; a
        # higher layer must corroborate it. This is the colliding-name guard.
        if top_layer <= LAYER_NARRATIVE:
            tier = "low"
        else:
            tier = (
                "high"
                if score >= self.TIER_HIGH
                else "medium"
                if score >= self.TIER_MEDIUM
                else "low"
            )
        return round(score, 2), tier

    def _classify_relationship(self, matched_headers, provider_headers):
        """DEPENDS_ON vs VENDORED, by how much of the provider's header surface a
        candidate reproduces. (GitHub-fork MIRRORs are applied by the
        orchestrator, which has the isFork metadata.)"""
        if (
            provider_headers >= self.COPY_MIN_HEADERS
            and matched_headers / provider_headers >= self.COPY_HEADER_FRACTION
        ):
            return "VENDORED"
        return "DEPENDS_ON"

    @staticmethod
    def _regexp_literal(regex):
        """Wrap a regex as a Sourcegraph slash-delimited pattern literal.

        A bare regex placed in a query lets Sourcegraph's parser interpret the
        pattern's parentheses/pipes as query operators; a large alternation like
        `(a|b|c)` then fails with "Unable To Process Query ... unclear
        parentheses". Delimiting with slashes marks the whole thing as a single
        regexp token, so its parens are unambiguous. Only unescaped `/` needs
        escaping to `\\/` (an already-escaped `\\/` is passed through)."""
        out, i = [], 0
        while i < len(regex):
            c = regex[i]
            if c == "\\" and i + 1 < len(regex):
                out.append(regex[i : i + 2])  # keep escape pairs intact
                i += 2
                continue
            if c == "/":
                out.append("\\/")
                i += 1
                continue
            out.append(c)
            i += 1
        return f"/{''.join(out)}/"

    @staticmethod
    def _match_lines(match):
        """Extract the matched source lines from a streaming content match,
        supporting both the chunkMatches (current) and lineMatches (legacy)
        shapes so classification can attribute evidence."""
        lines = []
        for cm in match.get("chunkMatches") or []:
            content = cm.get("content")
            if content:
                lines.extend(content.splitlines() or [content])
        for lm in match.get("lineMatches") or []:
            content = lm.get("line")
            if content:
                lines.append(content)
        return lines or [""]

    def _emit_sse(self, event, payload, log):
        """Handle one Server-Sent Event. Yields content-match dicts and returns
        True when the stream should stop (done/error)."""
        if event == "matches":
            try:
                items = json.loads(payload)
            except ValueError:
                return False
            # Yield every match; callers filter by type (content vs path).
            yield from items
            return False
        if event == "progress":
            try:
                progress = json.loads(payload)
            except ValueError:
                return False
            for skip in progress.get("skipped", []):
                reason = skip.get("reason", "")
                if "limit" in reason or "timed" in reason or "timeout" in reason:
                    log.info(
                        "Sourcegraph truncated results",
                        extra={
                            "reason": reason,
                            "title": skip.get("title"),
                            "message": skip.get("message"),
                        },
                    )
                    self._note_search_incomplete(
                        f"sourcegraph: {skip.get('title') or reason}", log
                    )
            return False
        if event == "alert":
            # An alert means the query was constrained or rejected outright — a
            # bad regex, for instance, yields zero matches. That must not be
            # INFO: it is the difference between "no dependents" and "the search
            # never ran" (see the HDF5 `c++/` regex-escape bug).
            try:
                alert = json.loads(payload)
                log.warning(
                    "Sourcegraph search alert (results constrained or query rejected)",
                    extra={
                        "title": alert.get("title"),
                        "description": alert.get("description"),
                    },
                )
            except ValueError:
                pass
            return False
        if event == "error":
            try:
                err = json.loads(payload)
                # NB: "message" is a reserved LogRecord field — putting it in
                # `extra` raises KeyError, so the original error logging crashed
                # rather than logged. Use a non-reserved key.
                log.warning(
                    "Sourcegraph stream error event",
                    extra={"sg_error": err.get("message")},
                )
                self._note_search_incomplete(
                    f"sourcegraph error: {err.get('message', 'unknown')}", log
                )
            except ValueError:
                pass
            return True
        if event == "done":
            return True
        return False

    def _stream_search(self, query_string, log, max_attempts=6):
        """Run a Sourcegraph streaming search, yielding content-match dicts.

        Replaces GraphQL pagination: one long-lived request returns every match
        up to the query's count, and reports truncation explicitly via the
        progress event's `skipped` reasons. Connection-level failures (429/5xx)
        are retried with backoff before any data is yielded; a mid-stream break
        keeps whatever was already collected."""
        headers = {
            "Authorization": f"token {self.args.sg_token}",
            "Accept": "text/event-stream",
        }
        params = {"q": query_string, "v": "V3"}

        resp = None
        backoff = 5
        for attempt in range(1, max_attempts + 1):
            try:
                resp = requests.get(
                    SOURCEGRAPH_STREAM_URL,
                    headers=headers,
                    params=params,
                    stream=True,
                    timeout=(15, 150),
                )
            except requests.exceptions.RequestException as e:
                log.debug(
                    "Sourcegraph stream connect failed",
                    extra={"attempt": attempt, "error": str(e)},
                )
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                wait = self._retry_after(resp, backoff)
                log.info(
                    f"Sourcegraph stream HTTP {resp.status_code}; backing off {wait}s",
                    extra={"attempt": attempt, "max_attempts": max_attempts},
                )
                resp.close()
                time.sleep(wait)
                backoff = min(backoff * 2, 120)
                continue

            if resp.status_code in (401, 403):
                # Auth failures never recover by retrying: surface loudly and
                # stop. A missing/expired SG token otherwise masquerades as "no
                # dependents found" after minutes of pointless backoff.
                log.error(
                    f"Sourcegraph auth failed (HTTP {resp.status_code}); check "
                    "SG_TOKEN. No dependents can be discovered without a valid token.",
                    extra={"status": resp.status_code, "body": resp.text[:300]},
                )
                resp.close()
                return

            if resp.status_code != 200:
                log.warning(
                    "Sourcegraph stream unexpected status",
                    extra={"status": resp.status_code, "body": resp.text[:300]},
                )
                resp.close()
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue
            break
        else:
            log.warning(
                "Sourcegraph stream abandoned after retries; results for this "
                "node may be incomplete."
            )
            self._note_search_incomplete(
                "sourcegraph: stream abandoned after retries", log
            )
            return

        event, data_lines = None, []
        try:
            for raw in resp.iter_lines(decode_unicode=True):
                if not raw:
                    # A blank line terminates the current event.
                    if event is not None:
                        stop = yield from self._emit_sse(
                            event, "\n".join(data_lines), log
                        )
                        if stop:
                            return
                    event, data_lines = None, []
                    continue
                if raw.startswith(":"):
                    continue  # keep-alive comment
                if raw.startswith("event:"):
                    event = raw[len("event:") :].strip()
                elif raw.startswith("data:"):
                    data_lines.append(raw[len("data:") :].lstrip())
        except requests.exceptions.RequestException as e:
            log.warning(
                "Sourcegraph stream interrupted; keeping partial results.",
                extra={"error": str(e)},
            )
            self._note_search_incomplete(
                "sourcegraph: stream interrupted mid-response", log
            )
        finally:
            resp.close()

    def discover_dependents(self, curr_id, curr_name, curr_sha, log):
        declared_aliases = (
            self._resolve_declared_aliases(curr_id, log)
            if self._enabled_registries()
            else {}
        )
        idset = self._compile_identifier_set(
            curr_id, curr_name, log, declared_aliases
        )
        protected_stems = {curr_name.lower()}
        patterns = self._patterns_from(idset, log, protected_stems)
        self.specificity.save()
        if not patterns:
            log.info("No search heuristics determined. Skipping.")
            return []
        compiled_patterns = [
            (p, re.compile(p.regex, re.IGNORECASE)) for p in patterns
        ]

        full_regex = f"({'|'.join(p.regex for p in patterns)})"
        fork_filter = "fork:yes" if self.args.forks else "fork:no"
        file_filter = f"file:{self.args.custom_file}" if self.args.custom_file else ""
        archived_filter = "archived:yes" if self.args.include_archived else ""
        vendor_filter = (
            ""
            if self.args.include_vendored
            else f"-file:(^|/)({'|'.join(self.VENDOR_DIRS)})/"
        )

        full_query = (
            f"context:global patternType:regexp {self._regexp_literal(full_regex)} "
            f"{fork_filter} {file_filter} {archived_filter} {vendor_filter} "
            f"count:{self.args.sg_count} timeout:2m"
        )

        if self.args.sg_delay > 0:
            time.sleep(self.args.sg_delay)

        log.info("Initiating Sourcegraph streaming dependency search")
        consumers = {}
        for match in self._stream_search(full_query, log):
            if match.get("type") != "content":
                continue
            rn = match.get("repository")
            if not rn:
                continue
            if rn not in consumers:
                consumers[rn] = {
                    "name": rn,
                    "url": f"https://{rn}",
                    "oid": match.get("commit", "HEAD"),
                    "evidence": {},
                    "identifiers": set(),
                    "kindWeights": {},
                    "matchedHeaders": set(),
                    "provenance": set(),
                    "matchCount": 0,
                }
            entry = consumers[rn]
            # A match inside documentation is weaker evidence of real usage than
            # one in source/build files; scale its weight contribution down.
            ctx = 0.3 if self._is_doc_path(match.get("path", "")) else 1.0
            for preview in self._match_lines(match):
                entry["matchCount"] += 1
                for pattern in self._classify(preview, compiled_patterns):
                    idf = pattern.identifier
                    entry["evidence"][pattern.evidence] = (
                        entry["evidence"].get(pattern.evidence, 0) + 1
                    )
                    entry["identifiers"].add(idf.value)
                    entry["kindWeights"][idf.kind] = max(
                        entry["kindWeights"].get(idf.kind, 0.0), pattern.weight * ctx
                    )
                    entry["provenance"].add(idf.provenance)
                    if idf.kind in self.HEADER_KINDS:
                        entry["matchedHeaders"].add(idf.value)

        if declared_aliases:
            self._merge_declared_dependents(consumers, declared_aliases, log)

        provider_headers = sum(1 for i in idset if i.kind in self.HEADER_KINDS)
        for entry in consumers.values():
            score, tier = self._score_consumer(
                entry["kindWeights"], entry["matchCount"]
            )
            layers = self._evidence_layers(entry["kindWeights"])
            entry["confidenceScore"] = score
            entry["confidence"] = tier
            entry["layers"] = layers
            entry["evidenceLayer"] = layers[-1] if layers else None
            entry["relationship"] = self._classify_relationship(
                len(entry["matchedHeaders"]), provider_headers
            )
            entry["identifiers"] = sorted(entry["identifiers"])
            entry["provenance"] = sorted(entry["provenance"])
            del entry["kindWeights"]
            del entry["matchedHeaders"]

        log.info(
            f"Sourcegraph dependency search completed. Found {len(consumers)} total consumers."
        )
        return list(consumers.values())


class AuditOrchestrator:
    def __init__(self, args, plugin: EcosystemPlugin, base_logger):
        self.args = args
        self.plugin = plugin
        self.citations = CitationEngine(args.email, args)
        self.github = GitHubEnricher(args.gh_token)
        self.spdx = SPDXManager()
        self.base_logger = base_logger
        self.run_id = str(uuid.uuid4())

        self.visited = set()
        self.nodes_map = {}
        self.edges_list = []
        self.incomplete_nodes = []  # repos whose citation search was partial

    def _build_node_data(
        self,
        repo_name,
        label,
        owner,
        type,
        depth,
        fallback_url,
        fallback_sha,
        log,
        rel_path="",
        discovery=None,
    ):
        meta = self.github.get_metadata(repo_name, log)
        full_url = fallback_url.replace("http://", "https://").rstrip("/")

        all_text = " ".join(
            filter(
                None,
                [
                    meta.get("readme"),
                    meta.get("description"),
                    meta.get("cff"),
                    meta.get("codemeta"),
                    meta.get("zenodo"),
                    meta.get("zenodo_alt"),
                ],
            )
        )

        target_urls = [full_url]
        if meta.get("homepageUrl"):
            target_urls.append(meta.get("homepageUrl"))
        if meta.get("description"):
            target_urls.extend(re.findall(r"(https?://[^\s]+)", meta["description"]))
        if meta.get("cff"):
            target_urls.extend(
                re.findall(
                    r'(?:url|value)\s*:\s*[\'"]?(https?://[^\s\'"]+)[\'"]?', meta["cff"]
                )
            )

        for jkey in ["codemeta", "zenodo", "zenodo_alt"]:
            if meta.get(jkey):
                try:

                    def find_urls(obj):
                        found = []
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                if (
                                    isinstance(v, str)
                                    and v.startswith("http")
                                    and k.lower()
                                    in ["url", "identifier", "@id", "relatedlink"]
                                ):
                                    found.append(v)
                                else:
                                    found.extend(find_urls(v))
                        elif isinstance(obj, list):
                            for item in obj:
                                found.extend(find_urls(item))
                        return found

                    target_urls.extend(find_urls(json.loads(meta[jkey])))
                except:
                    pass

        target_urls = sorted(set(target_urls))  # sorted: deterministic ordering

        # Only inject the academic keywords if we are scanning the root
        keywords = []
        if depth == 0 and self.args.academic_keyword:
            keywords = [kw.strip() for kw in self.args.academic_keyword.split(",")]

        # The deeper (multi-hop) citation crawl is expensive and noisy, so run
        # it only at the root node; every other node gets the direct-citer pass.
        citation_depth = CITATION_DEFAULT_DEPTH
        if depth == 0:
            citation_depth = self.args.citation_depth

        # Repo "profile" used by the paper-relevance scorer. Topics come from
        # GitHub repo topics plus any injected academic keywords; terms are the
        # most frequent significant tokens in the repo's own text. The bare
        # project-name token is EXCLUDED from terms (the "zfp" fix): a colliding
        # name must not corroborate an unrelated keyword-search paper.
        name_tokens = set(_tokenize(label)) | {label.lower()}
        profile = {
            "name": label,
            "owner": owner,
            "topics": {t.lower() for t in meta.get("topics", [])}
            | {k.lower() for k in keywords},
            "terms": _significant_terms(all_text, exclude=name_tokens),
            "seminal_authors": set(),
            "seminal_venues": set(),
        }

        papers, paper_diag = self.citations.get_publications(
            full_url, meta, target_urls, all_text, keywords, log,
            citation_depth=citation_depth, profile=profile,
        )
        if not paper_diag.get("complete"):
            self.incomplete_nodes.append(repo_name)

        return {
            "id": repo_name,
            "label": label,
            "type": type,
            "data": {
                "packageName": label,
                "packageOwner": owner,
                "originUrl": fallback_url,
                "commitSha": meta.get("commitSha", fallback_sha),
                "depth": depth,
                "snippetPath": rel_path,
                "stars": meta.get("stars", 0),
                "contributors": meta.get("contributors", 0),
                "commits": meta.get("commits", 0),
                "lastUpdate": meta.get("lastUpdate", ""),
                "latestRelease": meta.get("latestRelease", ""),
                "license": meta.get("license", "None"),
                "isFork": meta.get("isFork", False),
                "description": meta.get("description", ""),
                "papers": papers,
                "paperDiagnostics": paper_diag,
                "confidence": discovery.get("confidence") if discovery else None,
                "confidenceScore": discovery.get("confidenceScore", 0)
                if discovery
                else 0,
                "evidence": discovery.get("evidence", {}) if discovery else {},
                "identifiers": discovery.get("identifiers", []) if discovery else [],
                "provenance": discovery.get("provenance", []) if discovery else [],
                "evidenceLayer": discovery.get("evidenceLayer") if discovery else None,
                "layers": discovery.get("layers", []) if discovery else [],
                "relationship": discovery.get("relationship", "DEPENDS_ON")
                if discovery
                else None,
                "matchCount": discovery.get("matchCount", 0) if discovery else 0,
            },
        }

    def run(self):
        root_repo = self.args.repo.replace("github.com/", "")
        self.visited.add(root_repo)

        root_log = ContextAdapter(
            self.base_logger,
            {
                "run_id": self.run_id,
                "root_repo": root_repo,
                "plugin": self.plugin.__class__.__name__,
                "depth": 0,
                "chain": [root_repo],
            },
        )
        root_log.info("Booting Ecosystem Audit Engine")

        root_owner, r_name = self.github.parse_repo_info(root_repo)
        root_node = self._build_node_data(
            root_repo,
            r_name,
            root_owner,
            "library",
            0,
            f"https://github.com/{root_repo}",
            "HEAD",
            root_log,
        )
        self.nodes_map[root_repo] = root_node

        queue = deque(
            [
                (
                    self.args.repo,
                    self.args.name,
                    0,
                    root_node["data"]["commitSha"],
                    [root_repo],
                )
            ]
        )

        while queue:
            curr_id, curr_name, depth, curr_sha, chain = queue.popleft()

            if depth >= self.args.depth:
                node_log = ContextAdapter(
                    self.base_logger,
                    {
                        "run_id": self.run_id,
                        "root_repo": root_repo,
                        "plugin": self.plugin.__class__.__name__,
                        "depth": depth,
                        "chain": chain,
                    },
                )
                node_log.info(
                    f"Max depth {self.args.depth} reached. Halting discovery for this branch."
                )
                continue

            node_log = ContextAdapter(
                self.base_logger,
                {
                    "run_id": self.run_id,
                    "root_repo": root_repo,
                    "plugin": self.plugin.__class__.__name__,
                    "depth": depth,
                    "chain": chain,
                },
            )
            node_log.info("Evaluating dependent connections")

            consumers = self.plugin.discover_dependents(
                curr_id, curr_name, curr_sha, node_log
            )

            for child in consumers:
                child_full, child_sha = child["name"], child["oid"]
                clean_child = child_full.replace("github.com/", "")
                if clean_child == curr_id.replace("github.com/", ""):
                    continue

                child_chain = chain + [clean_child]
                child_log = ContextAdapter(
                    self.base_logger,
                    {
                        "run_id": self.run_id,
                        "root_repo": root_repo,
                        "plugin": self.plugin.__class__.__name__,
                        "depth": depth + 1,
                        "chain": child_chain,
                    },
                )

                child_owner, child_name = self.github.parse_repo_info(child_full)
                rel_path = self.spdx.generate_snippet(
                    clean_child,
                    curr_id.replace("github.com/", ""),
                    child_sha,
                    curr_sha,
                    self.github,
                    child_log,
                )

                if clean_child not in self.nodes_map:
                    self.nodes_map[clean_child] = self._build_node_data(
                        clean_child,
                        child_name,
                        child_owner,
                        "consumer",
                        depth + 1,
                        child["url"],
                        child_sha,
                        child_log,
                        rel_path,
                        discovery=child,
                    )

                # A GitHub-flagged fork of the provider is a MIRROR regardless of
                # how many headers it reproduces; otherwise use the discovery-time
                # relationship (DEPENDS_ON / VENDORED).
                relationship = child.get("relationship", "DEPENDS_ON")
                child_node = self.nodes_map.get(clean_child)
                if child_node and child_node["data"].get("isFork"):
                    relationship = "MIRROR"
                    child_node["data"]["relationship"] = "MIRROR"

                self.edges_list.append(
                    {
                        "source": clean_child,
                        "target": curr_id.replace("github.com/", ""),
                        "evidence": child.get("evidence", {}),
                        "identifiers": child.get("identifiers", []),
                        "provenance": child.get("provenance", []),
                        "evidenceLayer": child.get("evidenceLayer"),
                        "layers": child.get("layers", []),
                        "relationship": relationship,
                        "confidence": child.get("confidence"),
                        "confidenceScore": child.get("confidenceScore", 0),
                        "matchCount": child.get("matchCount", 0),
                    }
                )
                if clean_child not in self.visited:
                    self.visited.add(clean_child)
                    queue.append(
                        (child_full, child_name, depth + 1, child_sha, child_chain)
                    )

        completeness = self._build_completeness()
        with open(self.args.out, "w") as f:
            json.dump(
                {
                    "meta": {
                        "root": self.args.repo,
                        "ecosystem": self.args.ecosystem,
                        "schemaVersion": "2.3",
                        "completeness": completeness,
                    },
                    "nodes": list(self.nodes_map.values()),
                    "edges": self.edges_list,
                },
                f,
                indent=2,
            )
        self.citations.save()
        if completeness["complete"]:
            root_log.info(
                "Audit graph generation completed successfully (COMPLETE).",
                extra={"output_file": self.args.out},
            )
        else:
            root_log.warning(
                "Audit graph generation completed but is INCOMPLETE — see "
                "meta.completeness; a re-run may differ until the failing "
                "sources recover.",
                extra={
                    "output_file": self.args.out,
                    "warnings": completeness["warnings"],
                },
            )

    def _build_completeness(self):
        """Aggregate every partial-search signal into one run-level verdict, so
        it is obvious when the graph is NOT a complete search. Deterministic:
        sorted node lists, sorted warnings."""
        warnings = []

        # Discovery (Sourcegraph) — dependent edges.
        discovery_incomplete = bool(getattr(self.plugin, "search_incomplete", False))
        discovery_warnings = sorted(getattr(self.plugin, "search_warnings", []))
        warnings.extend(discovery_warnings)

        # Citations — per node, plus run-level JOSS seminal index.
        incomplete_nodes = sorted(set(self.incomplete_nodes))
        for repo in incomplete_nodes:
            node = self.nodes_map.get(repo)
            for w in (node or {}).get("data", {}).get(
                "paperDiagnostics", {}
            ).get("warnings", []):
                warnings.append(f"{repo} citations — {w}")

        joss_failed = getattr(self.citations.joss_plugin, "pages_failed", 0)
        joss_incomplete = joss_failed > 0
        if joss_incomplete:
            warnings.append(
                f"JOSS seminal index: {joss_failed} page(s) failed to load; "
                "some seminal DOIs may be missing"
            )

        complete = not (
            discovery_incomplete or incomplete_nodes or joss_incomplete
        )
        return {
            "complete": complete,
            "warnings": sorted(set(warnings)),
            "discovery": {
                "complete": not discovery_incomplete,
                "warnings": discovery_warnings,
            },
            "citations": {
                "complete": not incomplete_nodes,
                "incompleteNodes": incomplete_nodes,
            },
            "seminalIndex": {
                "complete": not joss_incomplete,
                "jossPagesFailed": joss_failed,
            },
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument(
        "--ecosystem", choices=["cpp", "rust", "python", "node"], default="cpp"
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Set to 0 to only audit papers/metadata for the root repo.",
    )
    parser.add_argument("--out", default="dependency_graph.json")
    parser.add_argument("--sg-token", default=os.environ.get("SG_TOKEN"))
    parser.add_argument("--gh-token", default=os.environ.get("GH_TOKEN"))
    parser.add_argument(
        "--email", default=os.environ.get("AUDIT_EMAIL", "audit-bot@example.com")
    )

    parser.add_argument(
        "--academic-keyword",
        help="Comma-separated keywords for full-text academic searching (e.g. 'dyninst')",
    )
    parser.add_argument(
        "--citation-depth",
        type=int,
        default=CITATION_DEFAULT_DEPTH,
        help="Hops to crawl the reverse-citation graph from seminal DOIs at the "
        "root node (1 = direct citers only; higher = citers-of-citers). "
        "Non-root nodes always use depth 1.",
    )
    parser.add_argument(
        "--no-paper-relevance",
        action="store_true",
        help="Disable paper-relevance scoring; emit every discovered paper "
        "unscored (historical behavior).",
    )
    parser.add_argument(
        "--paper-relevance-floor",
        choices=["low", "medium", "high"],
        default=os.environ.get("PAPER_RELEVANCE_FLOOR", "medium"),
        help="Lowest relevance tier kept in output when filtering is on "
        "(default: medium). Seminal papers are always kept.",
    )
    parser.add_argument(
        "--no-paper-filter",
        action="store_true",
        help="Keep low-relevance papers in output (scored but not dropped), "
        "so false positives stay scannable.",
    )
    parser.add_argument(
        "--relevance-llm-url",
        default=os.environ.get("RELEVANCE_LLM_URL"),
        help="Base URL of an OpenAI-compatible chat endpoint (llama.cpp / "
        "LMStudio / vLLM / Ollama) used to break ties on borderline papers. "
        "Off unless set. Bearer token via RELEVANCE_LLM_TOKEN.",
    )
    parser.add_argument(
        "--relevance-llm-model",
        default=os.environ.get("RELEVANCE_LLM_MODEL", "local-model"),
        help="Model name passed to the relevance LLM endpoint.",
    )
    parser.add_argument(
        "--paper-cache",
        default=os.environ.get("PAPER_CACHE", ".paper_cache.json"),
        help="Path to the persistent DOI-metadata backfill cache "
        "(empty string disables).",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--forks", action="store_true")
    parser.add_argument(
        "--include-archived",
        action="store_true",
        help="Include archived repositories in dependent results.",
    )
    parser.add_argument(
        "--include-vendored",
        action="store_true",
        help="Include matches inside vendored/third-party directories.",
    )
    parser.add_argument(
        "--sg-delay",
        type=float,
        default=float(os.environ.get("SG_DELAY", 0.0)),
        help="Seconds to wait before each Sourcegraph streaming search (throttle).",
    )
    parser.add_argument(
        "--sg-count",
        default=os.environ.get("SG_COUNT", "5000"),
        help="Max matches Sourcegraph collects per node (integer or 'all').",
    )
    parser.add_argument(
        "--no-idf",
        action="store_true",
        help="Disable IDF specificity gating of generic identifier tokens.",
    )
    parser.add_argument(
        "--idf-cache",
        default=os.environ.get("IDF_CACHE", ".idf_cache.json"),
        help="Path to the persistent IDF frequency cache (empty string disables).",
    )
    parser.add_argument(
        "--idf-cap",
        type=int,
        default=int(os.environ.get("IDF_CAP", 300)),
        help="Frequency-probe cap; tokens at/above this are treated as generic.",
    )
    parser.add_argument(
        "--declared-sources",
        default=os.environ.get("DECLARED_SOURCES", ""),
        help="Comma-separated package registries to corroborate against "
        "(e.g. 'spack'). Opt-in; off by default.",
    )
    parser.add_argument("--custom-string")
    parser.add_argument("--custom-file")
    parser.add_argument("--no-defaults", action="store_true")
    args = parser.parse_args()

    base_logger = setup_logger(args.verbose)

    if args.ecosystem == "cpp":
        if not args.sg_token and args.depth > 0:
            parser.error(
                "Sourcegraph token required for C++ searches (unless using depth 0)."
            )
        plugin = CppSourcegraphPlugin(args)
    else:
        raise NotImplementedError(
            f"Plugin for {args.ecosystem} is not yet implemented."
        )

    auditor = AuditOrchestrator(args, plugin, base_logger)
    auditor.run()

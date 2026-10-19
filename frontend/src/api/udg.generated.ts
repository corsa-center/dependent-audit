/* Generated from udg_schema.json by json-schema-to-typescript. Do not edit; run npm run gen:types. */

export interface UniversalDependencyGraph {
  meta: {
    root?: string;
    ecosystem?: string;
    schemaVersion?: string;
    /**
     * Whether this graph is a COMPLETE search. Determinism guarantee: two runs over the same live data agree; when a transient failure (rate limit, timeout) or a bounded cap makes a run partial, it is reported here rather than silently producing a smaller graph.
     */
    completeness?: {
      /**
       * True only when discovery, citations, and the seminal index all completed without dropped requests or truncation.
       */
      complete?: boolean;
      /**
       * Deterministic, human-readable list of everything that made the run partial.
       */
      warnings?: string[];
      /**
       * Sourcegraph dependent-search completeness (truncation / abandoned / interrupted streams).
       */
      discovery?: {
        [k: string]: unknown;
      };
      /**
       * Per-node citation completeness; incompleteNodes lists repos whose paper search was partial.
       */
      citations?: {
        [k: string]: unknown;
      };
      /**
       * JOSS seminal-DOI index load status (jossPagesFailed > 0 can hide seminal papers).
       */
      seminalIndex?: {
        [k: string]: unknown;
      };
      [k: string]: unknown;
    };
    [k: string]: unknown;
  };
  nodes: {
    id?: string;
    label?: string;
    type?: string;
    data?: {
      packageName?: string;
      packageOwner?: string;
      originUrl?: string;
      /**
       * Exact commit the node was audited at (HEAD when unknown).
       */
      commitSha?: string;
      /**
       * BFS hops from the root (0 = root).
       */
      depth?: number;
      /**
       * Relative path of this node's SPDX snippet (consumers only).
       */
      snippetPath?: string;
      description?: string;
      stars?: number;
      contributors?: number;
      commits?: number;
      lastUpdate?: string;
      latestRelease?: string;
      license?: string;
      isFork?: boolean;
      /**
       * Discovery confidence tier: high | medium | low | unknown
       */
      confidence?: "high" | "medium" | "low" | "unknown" | null;
      confidenceScore?: number;
      /**
       * Map of evidence type (vcs_ref, cmake_target, find_package, bazel, pkg_config, pragma_lib, include, executable, custom; a declared-interface consume entry defaults its evidence label to its kind) to number of matching lines observed.
       */
      evidence?: {
        [k: string]: number;
      };
      /**
       * Provider identifier values (header names, package names, ...) this consumer was observed referencing.
       */
      identifiers?: string[];
      /**
       * How the matched identifiers were learned (include_tree, cmake_config, cmake_project, pc_file, bazel_module, vcs, convention, declared:interface, ...).
       */
      provenance?: string[];
      /**
       * Strongest Axis-A evidence layer observed for this edge: 1 narrative, 2 source-consumption, 3 build-manifest, 4 package-registry, 5 binary/link, 6 attestation/SBOM, 7 bibliometric.
       */
      evidenceLayer?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | null;
      /**
       * All distinct Axis-A evidence layers observed for this edge (sorted). Cross-layer corroboration drives confidence.
       */
      layers?: (1 | 2 | 3 | 4 | 5 | 6 | 7)[];
      /**
       * Edge relationship: DEPENDS_ON | VENDORED (reproduces most of the provider's headers) | MIRROR (GitHub fork).
       */
      relationship?: "DEPENDS_ON" | "VENDORED" | "MIRROR" | null;
      matchCount?: number;
      papers?: {
        title?: string;
        doi?: string;
        journal?: string;
        url?: string;
        /**
         * Crossref is-referenced-by count.
         */
        citations?: number;
        /**
         * Hops from a seminal DOI in the reverse-citation crawl: 0 = seminal (the repo's own paper) or a direct text/full-text seed hit, 1 = direct citer, 2+ = citer-of-citer.
         */
        citationDepth?: number;
        /**
         * seminal when citationDepth == 0, else citing.
         */
        relation?: "seminal" | "citing";
        /**
         * Author display names (OpenAlex or Crossref).
         */
        authors?: string[];
        /**
         * Publication year.
         */
        year?: number | null;
        /**
         * OpenAlex concepts/topics (+ Crossref subjects) for the work.
         */
        concepts?: string[];
        /**
         * Discovery channels that surfaced this DOI; strongest relevance signal.
         */
        provenance?: (
          "seminal" | "reverse_citation" | "reverse_citation_oc" | "text_scrape" | "web_scrape" | "keyword_search"
        )[];
        /**
         * Paper-relevance corroboration score (provenance + author/term/concept/venue overlap).
         */
        relevanceScore?: number;
        /**
         * Relevance band from relevanceScore. Low-tier citing papers are dropped by default (see --no-paper-filter).
         */
        relevanceTier?: "low" | "medium" | "high";
        /**
         * Per-signal breakdown: provenance, sharedAuthors, matchedTerms, matchedConcepts, venue, channels, and optional llm verdict.
         */
        relevanceEvidence?: {
          [k: string]: unknown;
        };
        [k: string]: unknown;
      }[];
      /**
       * Completeness of THIS node's citation search. complete=false means a rate limit / timeout / cap dropped data, so the papers list may differ on another run.
       */
      paperDiagnostics?: {
        complete?: boolean;
        warnings?: string[];
        /**
         * Per-channel (openalex, opencitations, crossref) counts of dropped requests by kind (rate_limited, server_error, request_error, bad_response).
         */
        httpFailures?: {
          [k: string]: unknown;
        };
        /**
         * Bounded caps reached: citation_per_level, citation_total.
         */
        capsHit?: string[];
        doisSeen?: number;
        /**
         * DOIs that resolved to no metadata at all (dropped for lack of data, not low relevance).
         */
        doisUnresolved?: number;
        seminalFound?: number;
        [k: string]: unknown;
      };
      [k: string]: unknown;
    };
    [k: string]: unknown;
  }[];
  edges: {
    source: string;
    target: string;
    confidence?: string | null;
    confidenceScore?: number;
    evidence?: {
      [k: string]: number;
    };
    identifiers?: string[];
    provenance?: string[];
    evidenceLayer?: 1 | 2 | 3 | 4 | 5 | 6 | 7 | null;
    layers?: (1 | 2 | 3 | 4 | 5 | 6 | 7)[];
    relationship?: "DEPENDS_ON" | "VENDORED" | "MIRROR";
    matchCount?: number;
    [k: string]: unknown;
  }[];
  [k: string]: unknown;
}

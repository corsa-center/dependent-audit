import os
import time
import json
import argparse
import requests
import re
import concurrent.futures
import uuid
import logging
from collections import deque

SNIPPETS_DIR = "spdx_snippets"
SOURCEGRAPH_URL = "https://sourcegraph.com/.api/graphql"
JOSS_API_URL = "https://joss.theoj.org/papers/published.json"
CROSSREF_API_URL = "https://api.crossref.org/works/"
OPENCITATIONS_API_URL = "https://opencitations.net/index/api/v1/citations/"
DOI_REGEX = r'\b(10\.\d{4,9}/[-._;()/:A-Z0-9]+)\b'

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
            "message": record.getMessage()
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
        if 'extra' in kwargs: extra['extra_meta'] = kwargs.pop('extra')
        kwargs['extra'] = extra
        return msg, kwargs

def setup_logger(verbose):
    logger = logging.getLogger("DependencyAudit")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter() if verbose else TerseFormatter())
    logger.addHandler(handler)
    return logger

class PublicationPlugin:
    def __init__(self, email): self.email = email
    def initialize(self): pass

class SeminalDiscoveryPlugin(PublicationPlugin):
    def discover_seminal(self, repo_url, repo_meta, log): return set()

class JOSSPublicationPlugin(SeminalDiscoveryPlugin):
    def initialize(self):
        self.joss_map = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            for page_data in executor.map(self._fetch_joss_page, list(range(1, 300))):
                if not page_data: continue
                for paper in page_data:
                    repo_url = paper.get('repo_url', '').rstrip('/').replace('.git', '').replace('http://', 'https://')
                    if repo_url:
                        self.joss_map[repo_url.lower()] = {
                            "title": paper.get('title'), "doi": paper.get('doi'),
                            "joss_pdf": paper.get('paper_url'), "journal": "JOSS"
                        }
    def _fetch_joss_page(self, page):
        try:
            resp = requests.get(f"{JOSS_API_URL}?page={page}", timeout=10)
            if resp.status_code == 200: return resp.json()
        except Exception: pass
        return []
    def discover_seminal(self, repo_url, repo_meta, log):
        paper = self.joss_map.get(repo_url.lower())
        if paper and paper.get("doi"):
            log.debug("Found Seminal DOI via JOSS", extra={"doi": paper.get("doi")})
            return {paper.get("doi")}
        return set()

class CFFPublicationPlugin(SeminalDiscoveryPlugin):
    def discover_seminal(self, repo_url, repo_meta, log):
        cff_text = repo_meta.get("cff")
        if not cff_text: return set()
        dois = set(re.findall(r'(?:doi|identifier)\s*:\s*[\'"]?(10\.\d{4,9}/[-._;()/:A-Z0-9]+)[\'"]?', cff_text, re.IGNORECASE))
        if dois: log.debug("Found Seminal DOIs via CITATION.cff", extra={"dois": list(dois)})
        return dois

class ZenodoPublicationPlugin(SeminalDiscoveryPlugin):
    def discover_seminal(self, repo_url, repo_meta, log):
        dois = set()
        for jkey in ["zenodo", "zenodo_alt", "codemeta"]:
            if repo_meta.get(jkey):
                try:
                    data = json.loads(repo_meta[jkey])
                    doi = data.get("doi") or data.get("identifier")
                    if doi and doi.startswith("10."): dois.add(doi)
                except: pass
        readme = repo_meta.get("readme", "")
        dois.update(re.findall(r'(10\.5281/zenodo\.\d+)', readme, re.IGNORECASE))
        if dois: log.debug("Found Seminal DOIs via Zenodo/Codemeta", extra={"dois": list(dois)})
        return dois

class TextMatchPublicationPlugin(PublicationPlugin):
    def discover_dois(self, all_text, log):
        matches = set(re.findall(DOI_REGEX, all_text, re.IGNORECASE))
        return matches

class WebScrapePublicationPlugin(PublicationPlugin):
    def discover_dois(self, target_urls, log):
        found_dois = set()
        ignore = ['github.com', 'orcid.org', 'opensource.org', 'spdx.org', 'w3.org']
        for u in target_urls:
            if not u.startswith("http"): continue
            clean_url = u.strip().strip("'").strip('"')
            if any(domain in clean_url for domain in ignore) or any(clean_url.endswith(ext) for ext in ['.pdf', '.zip', '.tar.gz', '.png', '.jpg']): continue
            try:
                resp = requests.get(clean_url, headers={"User-Agent": "DependencyAuditBot/1.0"}, timeout=5)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    found_dois.update(re.findall(DOI_REGEX, resp.text, re.IGNORECASE))
            except: pass
        return found_dois

class OpenAlexPublicationPlugin(PublicationPlugin):
    def discover_citing(self, target_urls, seminal_dois, keywords, log):
        found_dois = set()
        
        search_terms = {f'"{u.replace("https://", "").replace("http://", "").rstrip("/")}"' for u in target_urls if u}
        if keywords:
            for kw in keywords: search_terms.add(f'"{kw}"')
            log.info(f"Injecting explicit academic keywords into OpenAlex search: {keywords}")

        for term in search_terms:
            cursor = "*"
            while cursor:
                try:
                    resp = requests.get("https://api.openalex.org/works", params={"search": term, "mailto": self.email, "per-page": 50, "cursor": cursor}, timeout=10)
                    if resp.status_code != 200: break
                    data = resp.json()
                    works = data.get("results", [])
                    if not works: break
                    for work in works:
                        if work.get("doi"): found_dois.add(work["doi"].replace("https://doi.org/", ""))
                    cursor = data.get("meta", {}).get("next_cursor")
                except Exception as e:
                    log.debug(f"OpenAlex full-text query failed for {term}", extra={"error": str(e)})
                    break
                    
        for doi in seminal_dois:
            cursor = "*"
            log.debug(f"OpenAlex reverse-citation lookup for Seminal DOI", extra={"doi": doi})
            while cursor:
                try:
                    resp = requests.get("https://api.openalex.org/works", params={"filter": f"cites:doi:{doi}", "mailto": self.email, "per-page": 50, "cursor": cursor}, timeout=10)
                    if resp.status_code != 200: break
                    data = resp.json()
                    works = data.get("results", [])
                    if not works: break
                    for work in works:
                        if work.get("doi"): found_dois.add(work["doi"].replace("https://doi.org/", ""))
                    cursor = data.get("meta", {}).get("next_cursor")
                except Exception as e:
                    log.debug(f"OpenAlex citation query failed for {doi}", extra={"error": str(e)})
                    break
        return found_dois

class OpenCitationsPlugin(PublicationPlugin):
    def discover_citing(self, seminal_dois, log):
        found_dois = set()
        for doi in seminal_dois:
            log.debug(f"OpenCitations reverse-citation lookup", extra={"doi": doi})
            try:
                resp = requests.get(f"{OPENCITATIONS_API_URL}{doi}", timeout=10)
                if resp.status_code == 200:
                    for item in resp.json():
                        if item.get("citing"): found_dois.add(item["citing"])
            except Exception as e:
                log.debug(f"OpenCitations query failed for {doi}", extra={"error": str(e)})
        return found_dois

class CrossrefPublicationPlugin(PublicationPlugin):
    def resolve_doi(self, doi, log):
        try:
            headers = {"User-Agent": f"DependencyAuditBot/1.0 (mailto:{self.email})"}
            resp = requests.get(f"{CROSSREF_API_URL}{doi}", headers=headers, timeout=5)
            if resp.status_code == 200:
                item = resp.json().get("message", {})
                res = {
                    "title": item.get("title", [""])[0], "doi": doi,
                    "journal": item.get("container-title", ["Unknown"])[0],
                    "citations": item.get("is-referenced-by-count", 0), "url": item.get("URL")
                }
                return res
        except: pass
        return None

class CitationEngine:
    def __init__(self, email):
        self.joss_plugin = JOSSPublicationPlugin(email)
        self.cff_plugin = CFFPublicationPlugin(email)
        self.zenodo_plugin = ZenodoPublicationPlugin(email)
        self.text_plugin = TextMatchPublicationPlugin(email)
        self.scrape_plugin = WebScrapePublicationPlugin(email)
        self.openalex_plugin = OpenAlexPublicationPlugin(email)
        self.opencitations_plugin = OpenCitationsPlugin(email)
        self.crossref_plugin = CrossrefPublicationPlugin(email)
        
        self.joss_plugin.initialize()

    def get_publications(self, repo_url, repo_meta, target_urls, all_text, keywords, log):
        seminal_dois = set()
        general_dois = set()

        seminal_dois.update(self.joss_plugin.discover_seminal(repo_url, repo_meta, log))
        seminal_dois.update(self.cff_plugin.discover_seminal(repo_url, repo_meta, log))
        seminal_dois.update(self.zenodo_plugin.discover_seminal(repo_url, repo_meta, log))

        if seminal_dois: log.info(f"Identified {len(seminal_dois)} Seminal DOIs for reverse-lookup.")

        general_dois.update(self.text_plugin.discover_dois(all_text, log))
        general_dois.update(self.scrape_plugin.discover_dois(target_urls, log))
        
        general_dois.update(self.openalex_plugin.discover_citing(target_urls, seminal_dois, keywords, log))
        
        general_dois.update(self.opencitations_plugin.discover_citing(seminal_dois, log))

        all_dois = seminal_dois.union(general_dois)
        papers = []
        
        log.debug(f"Resolving {len(all_dois)} unique DOIs via Crossref")
        for doi in all_dois:
            res = self.joss_plugin.joss_map.get(doi) 
            if not res: res = self.crossref_plugin.resolve_doi(doi, log)
            if res: papers.append(res)
            
        return papers


class GitHubEnricher:
    def __init__(self, gh_token):
        self.gh_token = gh_token

    def parse_repo_info(self, repo_full_name):
        clean = repo_full_name.replace("github.com/", "").replace("gitlab.com/", "").replace(".git", "")
        parts = clean.split("/")
        return (parts[0], parts[1]) if len(parts) >= 2 else ("unknown", clean)

    def get_metadata(self, repo_full_name, log):
        if not self.gh_token or "gitlab.com" in repo_full_name or "bitbucket.org" in repo_full_name: return {}
        owner, name = self.parse_repo_info(repo_full_name)
        if owner == "unknown": return {}
        
        query = """
        query($owner: String!, $name: String!) {
          repository(owner: $owner, name: $name) {
            isFork stargazerCount description homepageUrl licenseInfo { name } updatedAt
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
            resp = requests.post("https://api.github.com/graphql", headers={"Authorization": f"Bearer {self.gh_token}"}, json={"query": query, "variables": {"owner": owner, "name": name}}, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("repository")
                if data:
                    return {
                        "isFork": data.get("isFork", False), "stars": data.get("stargazerCount", 0),
                        "description": data.get("description", ""), "homepageUrl": data.get("homepageUrl", ""),
                        "license": data.get("licenseInfo", {}).get("name", "None") if data.get("licenseInfo") else "None",
                        "lastUpdate": data.get("updatedAt", ""),
                        "commitSha": data.get("defaultBranchRef", {}).get("target", {}).get("oid", "HEAD") if data.get("defaultBranchRef") else "HEAD",
                        "commits": data.get("defaultBranchRef", {}).get("target", {}).get("history", {}).get("totalCount", 0) if data.get("defaultBranchRef") else 0,
                        "latestRelease": data.get("releases", {}).get("nodes", [{"publishedAt": ""}])[0].get("publishedAt", "") if data.get("releases", {}).get("nodes") else "",
                        "contributors": data.get("mentionableUsers", {}).get("totalCount", 0) if data.get("mentionableUsers") else 0,
                        "readme": data.get("readme", {}).get("text", "") if data.get("readme") else "",
                        "cff": data.get("cff", {}).get("text", "") if data.get("cff") else "",
                        "codemeta": data.get("codemeta", {}).get("text", "") if data.get("codemeta") else "",
                        "zenodo": data.get("zenodo", {}).get("text", "") if data.get("zenodo") else "",
                        "zenodo_alt": data.get("zenodo_alt", {}).get("text", "") if data.get("zenodo_alt") else ""
                    }
        except Exception as e: log.debug(f"GH API Error", extra={"error": str(e)})
        return {}


class SPDXManager:
    def __init__(self, output_dir=SNIPPETS_DIR):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)

    def generate_snippet(self, consumer_repo, provider_repo, consumer_sha, provider_sha, github_enricher, log):
        c_owner, c_name = github_enricher.parse_repo_info(consumer_repo)
        p_owner, p_name = github_enricher.parse_repo_info(provider_repo)
        c_safe, p_safe = consumer_repo.replace("/", "-").replace(".", "-"), provider_repo.replace("/", "-").replace(".", "-")
        
        snippet = {
            "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{c_name} Dependency Manifest", "documentNamespace": f"https://github.com/{consumer_repo}/spdx/{consumer_sha}",
            "packages": [
                {"name": c_name, "SPDXID": f"SPDXRef-Package-{c_safe}", "versionInfo": consumer_sha, "downloadLocation": f"git+https://github.com/{consumer_repo}.git@{consumer_sha}", "filesAnalyzed": False},
                {"name": p_name, "SPDXID": f"SPDXRef-Package-{p_safe}", "versionInfo": provider_sha, "downloadLocation": f"git+https://github.com/{provider_repo}.git@{provider_sha}", "filesAnalyzed": False}
            ],
            "relationships": [{"spdxElementId": f"SPDXRef-Package-{c_safe}", "relatedSpdxElement": f"SPDXRef-Package-{p_safe}", "relationshipType": "DEPENDS_ON"}]
        }
        
        path = os.path.join(self.output_dir, f"{consumer_repo.replace('/', '_')}.spdx.json")
        with open(path, "w") as f: json.dump(snippet, f, indent=2)
        return path


class EcosystemPlugin:
    def __init__(self, args): self.args = args
    def discover_dependents(self, curr_id, curr_name, curr_sha, log): raise NotImplementedError()

class CppSourcegraphPlugin(EcosystemPlugin):
    def _graphql_query(self, query, variables, log, timeout=60):
        headers = {"Authorization": f"token {self.args.sg_token}", "Content-Type": "application/json"}
        log.debug("Executing Sourcegraph Query", extra={"query": query, "variables": variables})
        for _ in range(3):
            try:
                resp = requests.post(SOURCEGRAPH_URL, headers=headers, json={"query": query, "variables": variables}, timeout=timeout)
                if resp.status_code == 200: return resp.json()
                elif resp.status_code == 429: time.sleep(10)
                else: time.sleep(2)
            except Exception: time.sleep(2)
        return None

    def discover_dependents(self, curr_id, curr_name, curr_sha, log):
        search_id = curr_id if "github.com/" in curr_id else f"github.com/{curr_id}"
        
        tokens = []
        if not self.args.no_defaults:
            q_tokens = """query($repo: String!) { repository(name: $repo) { commit(rev: "HEAD") { tree(path: "include") { entries { name isDirectory } } } } }"""
            data = self._graphql_query(q_tokens, {"repo": search_id}, log)
            
            tree = {}
            if data and isinstance(data.get("data"), dict):
                repo_data = data["data"].get("repository")
                if isinstance(repo_data, dict):
                    commit_data = repo_data.get("commit")
                    if isinstance(commit_data, dict):
                        tree = commit_data.get("tree") or {}
                        
            if tree: tokens = [(e['name'], e['isDirectory']) for e in tree.get("entries", []) if curr_name.lower() in e['name'].lower()]
            if not tokens: tokens = [(f"{curr_name}.h", False), (f"{curr_name}", True)]
            
        regex_parts = []
        if tokens:
            for name, is_dir in tokens:
                safe = name.replace(".", "\\.")
                regex_parts.append(f'include\\s*[<\\x22]{safe}/.*[>\\x22]' if is_dir else f'include\\s*[<\\x22]{safe}[>\\x22]')
            regex_parts.append(f'pragma\\s+comment\\s*\\(\\s*lib\\s*,\\s*\\x22.*{curr_name}.*\\x22\\s*\\)')
        
        if not self.args.no_defaults:
            safe_name = curr_name.replace(".", "\\.")
            ci_name = "".join([f"[{c.lower()}{c.upper()}]" if c.isalpha() else c for c in safe_name])
            regex_parts.append(f'find_package\\s*\\(\\s*{ci_name}[\\s)]')
            regex_parts.append(f'pkg_check_modules\\s*\\([^)]*\\b{ci_name}\\b')

        if self.args.custom_string: regex_parts.append(self.args.custom_string)
        if not regex_parts: 
            log.info("No search heuristics determined. Skipping.")
            return []

        full_regex = f'({"|".join(regex_parts)})'
        fork_filter = "fork:yes" if self.args.forks else "fork:no"
        file_filter = f'file:{self.args.custom_file}' if self.args.custom_file else ""
        
        q_search = """query($query: String!) { search(query: $query) { results { limitHit results { ... on FileMatch { repository { name url } file { commit { oid } } } } } } }"""
        consumers, page = {}, 0
        
        log.info("Initiating Sourcegraph dependency search")
        while page < 30:
            page += 1
            exclude_clause = f" -repo:^({'|'.join([re.escape(n) for n in consumers.keys()])})$" if consumers else ""
            
            full_query = f'context:global patternType:regexp {full_regex} {fork_filter} {file_filter} archived:yes count:1000 timeout:2m{exclude_clause}'
            
            data = self._graphql_query(q_search, {"query": full_query}, log, timeout=150)
            if not data: break
                
            search_data = {}
            if data and isinstance(data.get("data"), dict):
                search_obj = data["data"].get("search")
                if isinstance(search_obj, dict):
                    search_data = search_obj.get("results") or {}
                    
            new_found = 0
            for hit in search_data.get("results", []):
                if "repository" in hit:
                    rn = hit["repository"]["name"]
                    if rn not in consumers:
                        consumers[rn] = {"name": rn, "url": hit["repository"]["url"], "oid": hit.get("file", {}).get("commit", {}).get("oid", "HEAD")}
                        new_found += 1
                        
            limit_hit = search_data.get("limitHit", False)
            log.debug(f"Sourcegraph pagination complete", extra={"page": page, "new_found": new_found, "limit_hit": limit_hit})
            if not limit_hit or (limit_hit and new_found == 0): break
            
        log.info(f"Sourcegraph dependency search completed. Found {len(consumers)} total consumers.")
        return list(consumers.values())


class AuditOrchestrator:
    def __init__(self, args, plugin: EcosystemPlugin, base_logger):
        self.args = args
        self.plugin = plugin
        self.citations = CitationEngine(args.email)
        self.github = GitHubEnricher(args.gh_token)
        self.spdx = SPDXManager()
        self.base_logger = base_logger
        self.run_id = str(uuid.uuid4())
        
        self.visited = set()
        self.nodes_map = {}
        self.edges_list = []

    def _build_node_data(self, repo_name, label, owner, type, depth, fallback_url, fallback_sha, log, rel_path=""):
        meta = self.github.get_metadata(repo_name, log)
        full_url = fallback_url.replace("http://", "https://").rstrip('/')
        
        all_text = " ".join(filter(None, [meta.get("readme"), meta.get("description"), meta.get("cff"), meta.get("codemeta"), meta.get("zenodo"), meta.get("zenodo_alt")]))
        
        target_urls = [full_url]
        if meta.get("homepageUrl"): target_urls.append(meta.get("homepageUrl"))
        if meta.get("description"): target_urls.extend(re.findall(r'(https?://[^\s]+)', meta["description"]))
        if meta.get("cff"): target_urls.extend(re.findall(r'(?:url|value)\s*:\s*[\'"]?(https?://[^\s\'"]+)[\'"]?', meta["cff"]))
            
        for jkey in ["codemeta", "zenodo", "zenodo_alt"]:
            if meta.get(jkey):
                try:
                    def find_urls(obj):
                        found = []
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                if isinstance(v, str) and v.startswith("http") and k.lower() in ["url", "identifier", "@id", "relatedlink"]: found.append(v)
                                else: found.extend(find_urls(v))
                        elif isinstance(obj, list):
                            for item in obj: found.extend(find_urls(item))
                        return found
                    target_urls.extend(find_urls(json.loads(meta[jkey])))
                except: pass
                    
        target_urls = list(set(target_urls))
        
        # Only inject the academic keywords if we are scanning the root
        keywords = []
        if depth == 0 and self.args.academic_keyword:
            keywords = [kw.strip() for kw in self.args.academic_keyword.split(",")]
            
        papers = self.citations.get_publications(full_url, meta, target_urls, all_text, keywords, log)

        return {
            "id": repo_name, "label": label, "type": type,
            "data": {
                "packageName": label, "packageOwner": owner, "originUrl": fallback_url, "commitSha": meta.get("commitSha", fallback_sha),
                "depth": depth, "snippetPath": rel_path, "stars": meta.get("stars", 0), "contributors": meta.get("contributors", 0),
                "commits": meta.get("commits", 0), "lastUpdate": meta.get("lastUpdate", ""), "latestRelease": meta.get("latestRelease", ""),
                "license": meta.get("license", "None"), "isFork": meta.get("isFork", False), "description": meta.get("description", ""), "papers": papers
            }
        }

    def run(self):
        root_repo = self.args.repo.replace("github.com/", "")
        self.visited.add(root_repo)
        
        root_log = ContextAdapter(self.base_logger, {"run_id": self.run_id, "root_repo": root_repo, "plugin": self.plugin.__class__.__name__, "depth": 0, "chain": [root_repo]})
        root_log.info(f"Booting Ecosystem Audit Engine")
        
        root_owner, r_name = self.github.parse_repo_info(root_repo)
        root_node = self._build_node_data(root_repo, r_name, root_owner, "library", 0, f"https://github.com/{root_repo}", "HEAD", root_log)
        self.nodes_map[root_repo] = root_node

        queue = deque([(self.args.repo, self.args.name, 0, root_node["data"]["commitSha"], [root_repo])])

        while queue:
            curr_id, curr_name, depth, curr_sha, chain = queue.popleft()
            
            if depth >= self.args.depth:
                node_log = ContextAdapter(self.base_logger, {"run_id": self.run_id, "root_repo": root_repo, "plugin": self.plugin.__class__.__name__, "depth": depth, "chain": chain})
                node_log.info(f"Max depth {self.args.depth} reached. Halting discovery for this branch.")
                continue
            
            node_log = ContextAdapter(self.base_logger, {"run_id": self.run_id, "root_repo": root_repo, "plugin": self.plugin.__class__.__name__, "depth": depth, "chain": chain})
            node_log.info(f"Evaluating dependent connections")
            
            consumers = self.plugin.discover_dependents(curr_id, curr_name, curr_sha, node_log)
            
            for child in consumers:
                child_full, child_sha = child['name'], child['oid']
                clean_child = child_full.replace("github.com/", "")
                if clean_child == curr_id.replace("github.com/", ""): continue
                
                child_chain = chain + [clean_child]
                child_log = ContextAdapter(self.base_logger, {"run_id": self.run_id, "root_repo": root_repo, "plugin": self.plugin.__class__.__name__, "depth": depth + 1, "chain": child_chain})
                
                child_owner, child_name = self.github.parse_repo_info(child_full)
                rel_path = self.spdx.generate_snippet(clean_child, curr_id.replace("github.com/", ""), child_sha, curr_sha, self.github, child_log)
                
                if clean_child not in self.nodes_map:
                    self.nodes_map[clean_child] = self._build_node_data(clean_child, child_name, child_owner, "consumer", depth + 1, child['url'], child_sha, child_log, rel_path)
                    
                self.edges_list.append({ "source": clean_child, "target": curr_id.replace("github.com/", "") })
                if clean_child not in self.visited:
                    self.visited.add(clean_child)
                    queue.append((child_full, child_name, depth + 1, child_sha, child_chain))
        
        with open(self.args.out, "w") as f:
            json.dump({ "meta": {"root": self.args.repo, "ecosystem": self.args.ecosystem}, "nodes": list(self.nodes_map.values()), "edges": self.edges_list }, f, indent=2)
        root_log.info("Audit graph generation completed successfully.", extra={"output_file": self.args.out})

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--ecosystem", choices=['cpp', 'rust', 'python', 'node'], default='cpp')
    parser.add_argument("--depth", type=int, default=1, help="Set to 0 to only audit papers/metadata for the root repo.")
    parser.add_argument("--out", default="dependency_graph.json")
    parser.add_argument("--sg-token", default=os.environ.get("SG_TOKEN"))
    parser.add_argument("--gh-token", default=os.environ.get("GH_TOKEN"))
    parser.add_argument("--email", default=os.environ.get("AUDIT_EMAIL", "audit-bot@example.com"))
    
    parser.add_argument("--academic-keyword", help="Comma-separated keywords for full-text academic searching (e.g. 'dyninst')")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--forks", action="store_true")
    parser.add_argument("--custom-string")
    parser.add_argument("--custom-file")
    parser.add_argument("--no-defaults", action="store_true")
    args = parser.parse_args()
    
    base_logger = setup_logger(args.verbose)
    
    if args.ecosystem == 'cpp':
        if not args.sg_token and args.depth > 0: parser.error("Sourcegraph token required for C++ searches (unless using depth 0).")
        plugin = CppSourcegraphPlugin(args)
    else:
        raise NotImplementedError(f"Plugin for {args.ecosystem} is not yet implemented.")
        
    auditor = AuditOrchestrator(args, plugin, base_logger)
    auditor.run()
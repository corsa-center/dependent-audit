import os
import time
import json
import argparse
import requests
import re
import concurrent.futures
from collections import deque

SNIPPETS_DIR = "spdx_snippets"
SOURCEGRAPH_URL = "https://sourcegraph.com/.api/graphql"
JOSS_API_URL = "https://joss.theoj.org/papers/published.json"
CROSSREF_API_URL = "https://api.crossref.org/works/"

DOI_REGEX = r'\b(10\.\d{4,9}/[-._;()/:A-Z0-9]+)\b'

def fetch_joss_page(page):
    try:
        url = f"{JOSS_API_URL}?page={page}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []

def load_joss_database():
    print("Booting concurrent JOSS scraper...")
    joss_map = {}
    pages_to_fetch = list(range(1, 300))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(fetch_joss_page, pages_to_fetch)
        for page_data in results:
            if not page_data:
                continue
            for paper in page_data:
                repo_url = paper.get('repo_url', '').rstrip('/').replace('.git', '').replace('http://', 'https://')
                if repo_url:
                    joss_map[repo_url.lower()] = {
                        "title": paper.get('title'),
                        "doi": paper.get('doi'),
                        "joss_pdf": paper.get('paper_url'),
                        "journal": "JOSS"
                    }
                    
    print(f"Successfully indexed {len(joss_map)} published JOSS papers.")
    return joss_map

def resolve_doi(doi, email="audit-bot@example.com"):
    try:
        url = f"{CROSSREF_API_URL}{doi}"
        headers = {"User-Agent": f"DependencyAuditBot/1.0 (mailto:{email})"}
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            item = resp.json().get("message", {})
            return {
                "title": item.get("title", [""])[0],
                "doi": doi,
                "journal": item.get("container-title", ["Unknown"])[0],
                "citations": item.get("is-referenced-by-count", 0),
                "url": item.get("URL")
            }
    except:
        pass
    return None

def search_openalex(target_urls, email="audit-bot@example.com"):
    found_dois = set()
    search_terms = set()
    
    for u in target_urls:
        if u:
            clean_url = u.replace("https://", "").replace("http://", "").rstrip('/')
            search_terms.add(f'"{clean_url}"')
            
    for term in search_terms:
        params = {
            "search": term,
            "mailto": email,
            "per-page": 50 
        }
        try:
            resp = requests.get("https://api.openalex.org/works", params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for work in data.get("results", []):
                    doi_url = work.get("doi")
                    if doi_url:
                        clean_doi = doi_url.replace("https://doi.org/", "")
                        found_dois.add(clean_doi)
        except Exception:
            pass
            
    return list(found_dois)

def parse_repo_info(repo_full_name):
    clean = repo_full_name.replace("github.com/", "").replace("gitlab.com/", "").replace(".git", "")
    parts = clean.split("/")
    return (parts[0], parts[1]) if len(parts) >= 2 else ("unknown", clean)

def get_github_metadata(repo_full_name, gh_token):
    if not gh_token: 
        print(f"Skipping GH Stats for {repo_full_name}: No GitHub Token provided.")
        return {}
        
    if "gitlab.com" in repo_full_name or "bitbucket.org" in repo_full_name:
        return {}
        
    owner, name = parse_repo_info(repo_full_name)
    if owner == "unknown": return {}
    
    query = """
    query($owner: String!, $name: String!) {
      repository(owner: $owner, name: $name) {
        isFork
        stargazerCount
        description
        homepageUrl
        licenseInfo { name }
        updatedAt
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
    headers = {"Authorization": f"Bearer {gh_token}"}
    try:
        resp = requests.post("https://api.github.com/graphql", headers=headers, json={"query": query, "variables": {"owner": owner, "name": name}}, timeout=15)
        if resp.status_code == 200:
            result = resp.json()
            if "errors" in result:
                print(f"GH API Warning for {repo_full_name}: {result['errors'][0].get('message')}")
            
            data = result.get("data", {}).get("repository")
            if data:
                return {
                    "isFork": data.get("isFork", False),
                    "stars": data.get("stargazerCount", 0),
                    "description": data.get("description", ""),
                    "homepageUrl": data.get("homepageUrl", ""),
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
    except Exception as e:
        print(f"GH API Error for {repo_full_name}: {e}")
    return {}

def graphql_query(query, variables, token, timeout=60):
    headers = {"Authorization": f"token {token}", "Content-Type": "application/json"}
    full_variables = {**variables, "patternType": "regexp"}
    for attempt in range(3):
        try:
            resp = requests.post(SOURCEGRAPH_URL, headers=headers, json={"query": query, "variables": full_variables}, timeout=timeout)
            if resp.status_code == 200: 
                return resp.json()
            elif resp.status_code == 429:
                print("Rate limited by Sourcegraph. Backing off for 10 seconds...")
                time.sleep(10)
            else:
                time.sleep(2)
        except requests.exceptions.Timeout:
            print(f"Query timed out on attempt {attempt + 1}. Retrying...")
            time.sleep(2)
        except Exception as e:
            time.sleep(2)
    return None

def get_public_search_tokens(repo_name, project_short_name, token):
    query = """
    query($repo: String!) {
      repository(name: $repo) {
        url
        commit(rev: "HEAD") { tree(path: "include") { entries { name isDirectory } } }
      }
    }
    """
    data = graphql_query(query, {"repo": repo_name}, token)
    if data and data.get("data", {}).get("repository") is None:
        if not repo_name.startswith("github.com/"):
            data = graphql_query(query, {"repo": f"github.com/{repo_name}"}, token)
    if not data: return [], ""
    repo = data.get("data", {}).get("repository", {})
    if not repo: return [], "" 
    commit = repo.get("commit", {})
    if not commit: return [(f"{project_short_name}.h", False), (f"{project_short_name}", True)], repo.get("url", "")
    tokens = []
    tree = commit.get("tree", {})
    if tree:
        for entry in tree.get("entries", []):
            if project_short_name.lower() in entry['name'].lower():
                tokens.append((entry['name'], entry['isDirectory']))
    if not tokens: tokens = [(f"{project_short_name}.h", False), (f"{project_short_name}", True)]
    return tokens, repo.get("url", "")

def find_consumers(search_tokens, lib_name, token, include_forks, custom_string, custom_file, use_defaults):
    regex_parts = []

    if use_defaults and search_tokens:
        for name, is_dir in search_tokens:
            safe = name.replace(".", "\\.")
            if is_dir: regex_parts.append(f'include\\s*[<\\x22]{safe}/.*[>\\x22]')
            else: regex_parts.append(f'include\\s*[<\\x22]{safe}[>\\x22]')
        regex_parts.append(f'pragma\\s+comment\\s*\\(\\s*lib\\s*,\\s*\\x22.*{lib_name}.*\\x22\\s*\\)')

    if custom_string:
        regex_parts.append(custom_string)

    if not regex_parts:
        return []

    full_regex = f'({"|".join(regex_parts)})'
    fork_filter = "fork:yes" if include_forks else "fork:no"
    file_filter = f'file:{custom_file}' if custom_file else ""
    
    query = """
    query($query: String!) {
      search(query: $query) {
        results { 
          limitHit
          results { 
            ... on FileMatch { 
              repository { name url } 
              file { commit { oid } }
            } 
          } 
        }
      }
    }
    """
    
    consumers = {}
    max_pages = 30  
    page = 0
    
    while page < max_pages:
        page += 1
        exclude_clause = ""
        
        if consumers:
            if len(consumers) > 3000:
                print("  -> WARNING: Ecosystem too large (>3000 direct consumers). Halting extraction to protect regex engine.")
                break
                
            escaped_repos = [re.escape(name) for name in consumers.keys()]
            exclude_clause = f" -repo:^({'|'.join(escaped_repos)})$"

        full_query = f'context:global {full_regex} {fork_filter} {file_filter} archived:yes count:1000 timeout:2m{exclude_clause}'
        
        data = graphql_query(query, {"query": full_query}, token, timeout=150)
        
        if not data:
            print("  -> ERR: Network or API failure during pagination. Halting search for this node.")
            break
            
        search_data = data.get("data", {}).get("search", {}).get("results", {})
        hits = search_data.get("results", [])
        
        new_found = 0
        for hit in hits:
            if "repository" in hit: 
                repo_name = hit["repository"]["name"]
                if repo_name not in consumers:
                    consumers[repo_name] = {
                        "name": repo_name,
                        "url": hit["repository"]["url"],
                        "oid": hit.get("file", {}).get("commit", {}).get("oid", "HEAD")
                    }
                    new_found += 1
                    
        limit_hit = search_data.get("limitHit", False)
        
        if page > 1 or limit_hit:
            print(f"  -> Page {page}: Found {new_found} new repositories. (Limit Hit: {limit_hit})")
        
        if not limit_hit:
            break  
            
        if limit_hit and new_found == 0:
            print("  -> WARNING: Sourcegraph timed out without yielding new results. Moving to next node.")
            break

    return list(consumers.values())

def generate_spdx_snippet(consumer_repo, provider_repo, consumer_sha, provider_sha):
    _, consumer_name = parse_repo_info(consumer_repo)
    _, provider_name = parse_repo_info(provider_repo)
    c_safe = consumer_repo.replace("/", "-").replace(".", "-")
    p_safe = provider_repo.replace("/", "-").replace(".", "-")
    
    snippet = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{consumer_name} Dependency Manifest",
        "documentNamespace": f"https://github.com/{consumer_repo}/spdx/{consumer_sha}",
        "packages": [
            {
                "name": consumer_name,
                "SPDXID": f"SPDXRef-Package-{c_safe}",
                "versionInfo": consumer_sha,
                "downloadLocation": f"git+https://github.com/{consumer_repo}.git@{consumer_sha}",
                "filesAnalyzed": False
            },
            {
                "name": provider_name,
                "SPDXID": f"SPDXRef-Package-{p_safe}",
                "versionInfo": provider_sha,
                "downloadLocation": f"git+https://github.com/{provider_repo}.git@{provider_sha}",
                "filesAnalyzed": False
            }
        ],
        "relationships": [
            {
                "spdxElementId": f"SPDXRef-Package-{c_safe}",
                "relatedSpdxElement": f"SPDXRef-Package-{p_safe}",
                "relationshipType": "DEPENDS_ON"
            }
        ]
    }
    safe_filename = consumer_repo.replace("/", "_") + ".spdx.json"
    path = os.path.join(SNIPPETS_DIR, safe_filename)
    with open(path, "w") as f: json.dump(snippet, f, indent=2)
    return path

def scrape_urls_for_dois(urls):
    found_dois = set()
    ignore_domains = ['github.com', 'orcid.org', 'opensource.org', 'spdx.org', 'w3.org']
    
    headers = {"User-Agent": "DependencyAuditBot/1.0"}
    for u in urls:
        if not u.startswith("http"): continue
        
        clean_url = u.strip().strip("'").strip('"')
        if any(domain in clean_url for domain in ignore_domains): continue
        if any(clean_url.endswith(ext) for ext in ['.pdf', '.zip', '.tar.gz', '.png', '.jpg']): continue
        
        try:
            resp = requests.get(clean_url, headers=headers, timeout=5)
            if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                page_dois = re.findall(DOI_REGEX, resp.text, re.IGNORECASE)
                found_dois.update(page_dois)
        except Exception:
            pass
            
    return list(found_dois)

def build_node_data(repo_name, label, owner, type, depth, gh_token, joss_map, fallback_url, fallback_sha, rel_path="", email="audit-bot@example.com"):
    meta = get_github_metadata(repo_name, gh_token)
    full_url = fallback_url.replace("http://", "https://").rstrip('/')
    
    papers = []
    found_dois = set()
    urls_to_scrape = set()
    
    paper_info = joss_map.get(full_url.lower())
    if paper_info:
        papers.append(paper_info)
        found_dois.add(paper_info.get("doi"))
        
    all_text = " ".join(filter(None, [
        meta.get("readme"), meta.get("description"), 
        meta.get("cff"), meta.get("codemeta"), 
        meta.get("zenodo"), meta.get("zenodo_alt")
    ]))
    found_dois.update(re.findall(DOI_REGEX, all_text, re.IGNORECASE))
    
    openalex_targets = [full_url]
    
    if meta.get("homepageUrl"):
        urls_to_scrape.add(meta["homepageUrl"])
        openalex_targets.append(meta["homepageUrl"])
        
    if meta.get("description"):
        desc_urls = re.findall(r'(https?://[^\s]+)', meta["description"])
        urls_to_scrape.update(desc_urls)
        if desc_urls and not meta.get("homepageUrl"):
            openalex_targets.append(desc_urls[0])
        
    if meta.get("cff"):
        cff_urls = re.findall(r'(?:url|value)\s*:\s*[\'"]?(https?://[^\s\'"]+)[\'"]?', meta["cff"])
        urls_to_scrape.update(cff_urls)
        
    for jkey in ["codemeta", "zenodo", "zenodo_alt"]:
        if meta.get(jkey):
            try:
                js_data = json.loads(meta[jkey])
                def find_urls_in_json(obj):
                    found = []
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if isinstance(v, str) and v.startswith("http"):
                                if k.lower() in ["url", "identifier", "@id", "relatedlink"]:
                                    found.append(v)
                            else:
                                found.extend(find_urls_in_json(v))
                    elif isinstance(obj, list):
                        for item in obj:
                            found.extend(find_urls_in_json(item))
                    return found
                urls_to_scrape.update(find_urls_in_json(js_data))
            except Exception:
                pass
                
    scraped_dois = scrape_urls_for_dois(urls_to_scrape)
    found_dois.update(scraped_dois)
    
    openalex_dois = search_openalex(openalex_targets, email)
    found_dois.update(openalex_dois)
    
    for doi in found_dois:
        if paper_info and paper_info.get("doi") == doi:
            continue
        resolved_paper = resolve_doi(doi, email)
        if resolved_paper:
            papers.append(resolved_paper)

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
            "papers": papers
        }
    }

def bfs_crawl(args):
    if not os.path.exists(SNIPPETS_DIR): os.makedirs(SNIPPETS_DIR)
    joss_map = load_joss_database()
    root_repo = args.repo
    visited = set()
    
    root_clean = root_repo.replace("github.com/", "")
    visited.add(root_clean)
    nodes_map = {}
    edges_list = []
    
    print(f"Starting Audit: {root_clean}")
    root_owner, r_name = parse_repo_info(root_clean)
    
    root_node = build_node_data(root_clean, r_name, root_owner, "library", 0, args.gh_token, joss_map, f"https://github.com/{root_clean}", "HEAD", "", args.email)
    nodes_map[root_clean] = root_node
    root_sha = root_node["data"]["commitSha"]

    queue = deque([(root_repo, args.name, 0, root_sha)])

    while queue:
        curr_id, curr_name, depth, curr_sha = queue.popleft()
        if depth > args.depth: continue
        search_id = curr_id if "github.com/" in curr_id else f"github.com/{curr_id}"
        print(f"Scanning: {search_id} @ {curr_sha[:7]}")
        
        tokens = []
        if not args.no_defaults:
            tokens, _ = get_public_search_tokens(search_id, curr_name, args.sg_token)
        
        consumers = find_consumers(
            tokens, curr_name, args.sg_token, args.forks, 
            args.custom_string, args.custom_file, not args.no_defaults
        )
        print(f"Found {len(consumers)} consumers.")
        
        for child in consumers:
            child_full = child['name'] 
            child_sha = child['oid']
            clean_child = child_full.replace("github.com/", "")
            
            if clean_child == curr_id.replace("github.com/", ""): continue
            
            child_owner, child_name = parse_repo_info(child_full)
            rel_path = generate_spdx_snippet(clean_child, curr_id.replace("github.com/", ""), child_sha, curr_sha)
            
            if clean_child not in nodes_map:
                nodes_map[clean_child] = build_node_data(
                    clean_child, child_name, child_owner, "consumer", depth + 1, 
                    args.gh_token, joss_map, child['url'], child_sha, rel_path, args.email
                )
                
            edges_list.append({ "source": clean_child, "target": curr_id.replace("github.com/", "") })
            if clean_child not in visited:
                visited.add(clean_child)
                queue.append((child_full, child_name, depth + 1, child_sha))
    
    with open(args.out, "w") as f:
        json.dump({ "meta": {"root": root_repo}, "nodes": list(nodes_map.values()), "edges": edges_list }, f, indent=2)
    print(f"Graph saved to {args.out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, help="Target repository (Owner/Repo)")
    parser.add_argument("--name", required=True, help="Project name to search for")
    parser.add_argument("--depth", type=int, default=1, help="Max recursion depth")
    parser.add_argument("--out", default="dependency_graph.json", help="Output JSON filename")
    parser.add_argument("--sg-token", default=os.environ.get("SG_TOKEN"), help="Sourcegraph Access Token (or set SG_TOKEN env var)")
    parser.add_argument("--gh-token", default=os.environ.get("GH_TOKEN"), help="GitHub PAT for metadata (or set GH_TOKEN env var)")
    parser.add_argument("--email", default=os.environ.get("AUDIT_EMAIL", "audit-bot@example.com"), help="Email for API polite pools (or set AUDIT_EMAIL env var)")
    parser.add_argument("--forks", action="store_true", help="Include forks in search results")
    parser.add_argument("--custom-string", help="Custom regex string to search for")
    parser.add_argument("--custom-file", help="Filename to restrict search to")
    parser.add_argument("--no-defaults", action="store_true", help="Disable default C++ header search")
    args = parser.parse_args()
    
    if not args.sg_token:
        parser.error("Sourcegraph token is required. Provide it via --sg-token or the SG_TOKEN environment variable.")
        
    bfs_crawl(args)
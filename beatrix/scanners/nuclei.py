"""
BEATRIX Nuclei Scanner Wrapper

Wraps the nuclei binary to integrate its massive template library
into Beatrix's scanning pipeline.

Nuclei has 12,600+ templates covering:
- CVEs, default logins, exposed panels
- Misconfigurations, technologies, takeovers
- WAF detection, tokens, fuzzing, OAST
- Cloud misconfigs, API exposure, secrets

This wrapper:
1. Checks that nuclei binary exists
2. Ensures templates are downloaded and fresh (auto-update >7 days)
3. Builds dynamic tag filters from detected technologies
4. Runs nuclei with JSONL output, streaming findings in real time
5. Captures stderr for progress logging
6. Parses each finding into Beatrix Finding objects
7. Maps nuclei severity to Bugcrowd VRT-aligned severity

Timeout strategy:
- Wall-clock timeout scales with URL count (base 600s + 0.5s per URL)
- Per-line readline timeout is generous (120s) so nuclei isn't killed
  during slow template batches that produce no output for a while
- The kill chain's own SCANNER_TIMEOUT (300s) is the outer bound;
  nuclei's internal timeout is capped to not exceed it
"""

import asyncio
import json
import os
import shutil
import time
from pathlib import Path
from typing import AsyncIterator, Dict, List, Optional

from beatrix.core.types import Confidence, Finding, Severity

from .base import BaseScanner, ScanContext

# Map nuclei severity strings to Beatrix Severity
NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiScanner(BaseScanner):
    """
    Nuclei template scanner — wraps the nuclei binary.

    Runs nuclei's 8000+ community templates against the target
    and converts results to Beatrix findings.

    Dynamic template selection:
    - Base tags always run (misconfig, exposure, cve, etc.)
    - Technology-specific tags added based on crawler fingerprint
    - Templates auto-updated if stale (>7 days)
    """

    name = "nuclei"
    description = "Nuclei template scanner — CVEs, misconfigs, exposed panels, takeovers"
    version = "2.0.0"

    # Map detected technologies to nuclei template tags
    TECH_TAG_MAP = {
        # Web servers
        "nginx": ["nginx"],
        "apache": ["apache", "httpd"],
        "iis": ["iis", "microsoft"],
        "caddy": ["caddy"],
        "tomcat": ["tomcat", "apache"],
        "lighttpd": ["lighttpd"],
        # CMS / Frameworks
        "wordpress": ["wordpress", "wp-plugin", "wp-theme"],
        "joomla": ["joomla"],
        "drupal": ["drupal"],
        "magento": ["magento"],
        "shopify": ["shopify"],
        "ghost": ["ghost"],
        "hugo": ["hugo"],
        # Languages / Runtimes
        "php": ["php"],
        "asp.net": ["asp", "dotnet", "microsoft"],
        "java": ["java", "spring"],
        "spring": ["spring", "springboot"],
        "python": ["python", "django", "flask"],
        "django": ["django"],
        "flask": ["flask"],
        "laravel": ["laravel", "php"],
        "rails": ["rails", "ruby"],
        "express": ["nodejs", "express"],
        "node": ["nodejs"],
        "next.js": ["nextjs"],
        "nuxt": ["nuxt"],
        # Infrastructure
        "cloudflare": ["cloudflare"],
        "aws": ["aws", "amazon"],
        "azure": ["azure", "microsoft"],
        "gcp": ["gcp", "google"],
        # Panels / Services
        "jenkins": ["jenkins"],
        "gitlab": ["gitlab"],
        "grafana": ["grafana"],
        "kibana": ["kibana"],
        "elasticsearch": ["elasticsearch"],
        "prometheus": ["prometheus"],
        "docker": ["docker"],
        "kubernetes": ["kubernetes", "k8s"],
        "traefik": ["traefik"],
        "consul": ["consul"],
        "vault": ["vault"],
        "minio": ["minio"],
        "redis": ["redis"],
        "mongodb": ["mongodb"],
        "mysql": ["mysql"],
        "postgres": ["postgres"],
        "rabbitmq": ["rabbitmq"],
        "kafka": ["kafka"],
        "solr": ["solr"],
    }

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.nuclei_path = self._find_nuclei()
        # Base timeout — scaled dynamically by _calculate_timeout() based on
        # URL count.  600s (10 min) is reasonable for a few hundred URLs.
        self._base_timeout = self.config.get("nuclei_timeout", 600)
        self.timeout_seconds = self._base_timeout
        self._urls_to_scan: List[str] = []
        # Include info severity — nuclei info templates detect tech, panels,
        # WAFs, exposed configs, and other recon-valuable data.
        self._severity_filter = self.config.get(
            "nuclei_severity", "critical,high,medium,low,info"
        )
        self._detected_technologies: List[str] = []
        self._template_dir = Path.home() / "nuclei-templates"
        self._templates_verified = False

    def _find_nuclei(self) -> Optional[str]:
        """Find nuclei binary on PATH"""
        path = shutil.which("nuclei")
        if path:
            return path
        # Check common locations
        for candidate in ["/usr/bin/nuclei", "/usr/local/bin/nuclei",
                         str(Path.home() / "go/bin/nuclei"),
                         str(Path.home() / ".local/bin/nuclei")]:
            if Path(candidate).exists():
                return candidate
        return None

    @property
    def available(self) -> bool:
        return self.nuclei_path is not None

    async def _ensure_templates(self) -> bool:
        """Ensure nuclei templates are installed and reasonably fresh.

        Auto-updates if templates are missing or >7 days old.
        Returns True if templates are available, False otherwise.
        """
        if self._templates_verified:
            return True

        if not self.nuclei_path:
            return False

        # Check if templates directory exists and has content
        template_marker = self._template_dir / ".checksum"
        needs_update = False

        if not self._template_dir.exists() or not any(self._template_dir.glob("**/*.yaml")):
            self.log("Nuclei templates not found — downloading...")
            needs_update = True
        elif template_marker.exists():
            age_days = (time.time() - template_marker.stat().st_mtime) / 86400
            if age_days > 7:
                self.log(f"Nuclei templates are {age_days:.0f} days old — updating...")
                needs_update = True
        else:
            # Templates exist but no checksum — count them
            pass

        if needs_update:
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.nuclei_path, "-update-templates", "-silent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=60)
                self.log("Nuclei templates updated")
            except (asyncio.TimeoutError, Exception) as e:
                self.log(f"Template update failed: {e} — proceeding with existing")

        # Count available templates
        yaml_count = sum(1 for _ in self._template_dir.glob("**/*.yaml")) if self._template_dir.exists() else 0
        self.log(f"Nuclei templates available: {yaml_count}")
        self._templates_verified = yaml_count > 0
        return self._templates_verified

    async def diagnostics(self) -> Dict:
        """Run nuclei diagnostics — verify binary, templates, and version.

        Use this to verify nuclei is working correctly:
            scanner = NucleiScanner()
            diag = await scanner.diagnostics()
            print(diag)
        """
        result = {
            "binary": self.nuclei_path,
            "available": self.available,
            "version": None,
            "template_dir": str(self._template_dir),
            "template_count": 0,
            "templates_by_severity": {},
            "tags_available": [],
        }

        if not self.nuclei_path:
            result["error"] = "nuclei binary not found"
            return result

        # Get version
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            version_text = (stdout or stderr).decode("utf-8", errors="replace").strip()
            result["version"] = version_text.split("\n")[0] if version_text else "unknown"
        except Exception as e:
            result["version"] = f"error: {e}"

        # Count templates by type
        if self._template_dir.exists():
            for yaml_file in self._template_dir.glob("**/*.yaml"):
                result["template_count"] += 1
                parent = yaml_file.parent.name
                result["templates_by_severity"][parent] = (
                    result["templates_by_severity"].get(parent, 0) + 1
                )

        # Ensure templates are fresh
        await self._ensure_templates()

        return result

    def add_urls(self, urls: List[str]) -> None:
        """Add URLs to scan — called by kill chain to feed discovered URLs."""
        self._urls_to_scan.extend(urls)

    def set_technologies(self, technologies) -> None:
        """Set detected technologies for dynamic template selection.

        Accepts either a list of strings or a dict (keys are tech names).
        """
        if isinstance(technologies, dict):
            self._detected_technologies = [t.lower() for t in technologies.keys()]
        else:
            self._detected_technologies = [t.lower() for t in technologies]

    def _calculate_timeout(self, url_count: int) -> int:
        """Calculate wall-clock timeout based on URL count.

        Base is 600s.  Add 0.5s per URL beyond 100 to give nuclei
        enough time for large scans.  Capped at 1800s (30 min).
        """
        extra = max(0, url_count - 100) * 0.5
        return min(int(self._base_timeout + extra), 1800)

    def _build_tags(self) -> str:
        """Build nuclei tag filter based on detected technologies.

        Uses a comprehensive base set that covers every high-value template
        category in nuclei-templates.  Technology-specific tags are added
        on top based on the crawler's fingerprint.
        """
        # Comprehensive base tags — covers all major template categories.
        # These use OR logic: a template matching ANY of these tags will run.
        tags = {
            # Vulnerability classes
            "cve", "rce", "lfi", "xss", "sqli", "ssrf", "idor",
            "xxe", "ssti", "cmdi", "traversal",
            # Misconfigurations & exposure
            "misconfig", "exposure", "config", "disclosure",
            "unauth", "default-login", "login",
            # Secrets & tokens
            "token", "secret", "api", "apikey", "keys",
            # Takeover & DNS
            "takeover", "dns",
            # Panels & admin
            "panel", "admin", "dashboard",
            # File & upload
            "fileupload", "file", "backup",
            # Cookies & headers
            "cookies", "cookie", "headers",
            # Redirect & injection
            "redirect", "injection", "intrusive",
            # Cloud
            "cloud", "aws", "azure", "gcp",
            # Detection & tech
            "tech", "detect", "waf",
            # Fuzzing & OAST (out-of-band)
            "fuzz", "oast",
            # Brute force & auth
            "bruteforce", "auth",
            # Misc high-value
            "creds", "debug", "log", "logs",
            "env", "git", "svn", "hg",
        }

        # Add technology-specific tags based on fingerprint
        for tech in self._detected_technologies:
            tech_lower = tech.lower().strip()
            for key, tech_tags in self.TECH_TAG_MAP.items():
                if key in tech_lower:
                    tags.update(tech_tags)

        return ",".join(sorted(tags))

    async def scan(self, context: ScanContext) -> AsyncIterator[Finding]:
        """Run nuclei against the target"""
        if not self.nuclei_path:
            self.log("nuclei binary not found — skipping (install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)")
            return

        # Ensure templates are downloaded and fresh
        if not await self._ensure_templates():
            self.log("No nuclei templates available — skipping")
            return

        # Pick up technologies from scan context if available
        if context.extra and context.extra.get("technologies"):
            self.set_technologies(context.extra["technologies"])

        # Build URL list: context URL + any additional URLs added by engine
        urls = set()
        urls.add(context.url)
        urls.update(self._urls_to_scan)

        # Build dynamic tags based on target fingerprint
        tags = self._build_tags()

        # Scale timeout based on URL count
        self.timeout_seconds = self._calculate_timeout(len(urls))
        self.log(f"Running nuclei on {len(urls)} URLs (timeout {self.timeout_seconds}s)")
        self.log(f"Tags: {tags}")

        # Run nuclei with JSON output
        async for finding in self._run_nuclei(list(urls), tags):
            yield finding

    async def _run_nuclei(self, urls: List[str], tags: str = "") -> AsyncIterator[Finding]:
        """Execute nuclei and stream findings"""
        import tempfile

        if not tags:
            tags = self._build_tags()

        # Write URLs to temp file for -l flag
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for url in urls:
                f.write(url + '\n')
            url_file = f.name

        try:
            cmd = [
                self.nuclei_path,
                "-l", url_file,
                "-jsonl",                    # JSON Lines output — findings to stdout
                "-silent",                   # Suppress banner noise
                "-no-color",                 # No ANSI colors in output
                "-timeout", "15",            # Per-request timeout (seconds)
                "-retries", "1",             # Don't retry failed requests
                "-rate-limit", "150",        # Requests per second
                "-bulk-size", "50",          # Concurrent templates per host
                "-concurrency", "25",        # Concurrent hosts
                "-severity", self._severity_filter,
                "-tags", tags,
                "-stats",                    # Show progress stats (stderr)
                "-stats-interval", "15",     # Stats every 15s
            ]

            self.log(f"Executing: {' '.join(cmd[:5])}...")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,   # Capture stderr for progress/errors
                limit=1024 * 1024,  # 1MB line buffer (nuclei can output long lines)
            )

            findings_count = 0
            wall_start = time.monotonic()

            # Readline timeout: how long we wait for ANY stdout output
            # before assuming nuclei is done or stuck.  120s is generous —
            # nuclei may go quiet for 30-60s between template batches but
            # should not be silent for 2+ minutes if it's still working.
            readline_timeout = 120

            # Background task to drain stderr and log progress
            stderr_lines: List[str] = []

            async def _drain_stderr():
                """Read stderr in background so the pipe doesn't block."""
                try:
                    while True:
                        raw = await process.stderr.readline()
                        if not raw:
                            break
                        text = raw.decode("utf-8", errors="replace").strip()
                        if text:
                            stderr_lines.append(text)
                            # Log stats/progress lines so the user sees activity
                            if any(kw in text.lower() for kw in
                                   ("templates", "hosts", "requests", "errors",
                                    "matched", "duration", "rps")):
                                self.log(f"[nuclei] {text}")
                except Exception:
                    pass

            stderr_task = asyncio.create_task(_drain_stderr())

            # Stream stdout line by line (JSONL findings)
            try:
                while True:
                    # Overall wall-clock timeout
                    elapsed = time.monotonic() - wall_start
                    if elapsed >= self.timeout_seconds:
                        self.log(f"Nuclei wall-clock timeout after {int(elapsed)}s")
                        process.kill()
                        break

                    remaining = self.timeout_seconds - elapsed
                    per_line_timeout = min(readline_timeout, remaining)

                    try:
                        line = await asyncio.wait_for(
                            process.stdout.readline(),
                            timeout=per_line_timeout
                        )
                    except asyncio.TimeoutError:
                        actual_elapsed = time.monotonic() - wall_start
                        if actual_elapsed >= self.timeout_seconds - 1:
                            self.log(
                                f"Nuclei timed out after {int(actual_elapsed)}s "
                                f"(wall-clock limit {self.timeout_seconds}s)"
                            )
                        else:
                            self.log(
                                f"Nuclei no stdout for {readline_timeout}s — "
                                f"assuming complete ({int(actual_elapsed)}s elapsed)"
                            )
                        process.kill()
                        break

                    if not line:
                        # EOF — nuclei exited normally
                        break

                    decoded = line.decode('utf-8', errors='replace').strip()
                    if not decoded:
                        continue

                    # Parse JSONL finding
                    try:
                        data = json.loads(decoded)
                        finding = self._parse_nuclei_finding(data)
                        if finding:
                            findings_count += 1
                            yield finding
                    except json.JSONDecodeError:
                        # Non-JSON line (shouldn't happen with -jsonl -silent)
                        continue
            finally:
                stderr_task.cancel()
                try:
                    await stderr_task
                except (asyncio.CancelledError, Exception):
                    pass

            await process.wait()
            total_elapsed = int(time.monotonic() - wall_start)
            self.log(f"Nuclei complete: {findings_count} findings in {total_elapsed}s")

            # Log the last few stderr lines (usually the scan summary)
            if stderr_lines:
                for sline in stderr_lines[-5:]:
                    self.log(f"[nuclei stderr] {sline}")

        except Exception as e:
            self.log(f"Nuclei error: {e}")
        finally:
            # Clean up temp file
            try:
                Path(url_file).unlink()
            except Exception:
                pass

    def _parse_nuclei_finding(self, data: Dict) -> Optional[Finding]:
        """Convert a nuclei JSON result to a Beatrix Finding"""
        try:
            info = data.get("info", {})
            template_id = data.get("template-id", data.get("templateID", "unknown"))
            matched_at = data.get("matched-at", data.get("matched", ""))

            # Severity mapping
            sev_str = info.get("severity", "info").lower()
            severity = NUCLEI_SEVERITY_MAP.get(sev_str, Severity.INFO)

            # Build title
            name = info.get("name", template_id)
            title = f"[Nuclei] {name}"

            # Build description
            desc_parts = []
            if info.get("description"):
                desc_parts.append(info["description"])

            tags = info.get("tags", [])
            if tags:
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",")]
                desc_parts.append(f"Tags: {', '.join(tags)}")

            if info.get("reference"):
                refs = info["reference"]
                if isinstance(refs, list):
                    desc_parts.append("References:\n" + "\n".join(f"- {r}" for r in refs))

            description = "\n\n".join(desc_parts) if desc_parts else f"Nuclei template {template_id} matched"

            # Build evidence
            evidence_parts = [f"Template: {template_id}"]

            matcher_name = data.get("matcher-name", data.get("matcher_name", ""))
            if matcher_name:
                evidence_parts.append(f"Matcher: {matcher_name}")

            extracted = data.get("extracted-results", data.get("extracted_results", []))
            if extracted:
                evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")

            curl_cmd = data.get("curl-command", data.get("curl_command", ""))
            if curl_cmd:
                evidence_parts.append(f"Reproduce: {curl_cmd}")

            evidence = "\n".join(evidence_parts)

            # Confidence based on severity and template type
            confidence = Confidence.FIRM
            if sev_str in ("critical", "high"):
                confidence = Confidence.CERTAIN
            elif sev_str == "info":
                confidence = Confidence.FIRM

            # References
            refs = info.get("reference", [])
            if isinstance(refs, str):
                refs = [refs]

            return Finding(
                title=title,
                severity=severity,
                confidence=confidence,
                url=matched_at,
                description=description,
                evidence=evidence,
                remediation=info.get("remediation", ""),
                references=refs if isinstance(refs, list) else [],
                scanner_module="nuclei",
            )

        except Exception as e:
            self.log(f"Failed to parse nuclei finding: {e}")
            return None

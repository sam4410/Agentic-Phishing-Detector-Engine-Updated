# ========================================
# File: tools.py
# ========================================
import os
import re
import tldextract
import validators
from typing import Dict, List, ClassVar
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from crewai_tools import BaseTool
from config import Config
from datetime import datetime
import whois
from config import Config
from util_funcs import is_exact_legitimate_domain, flatten_legitimate_domains


def get_domain_age_days(domain: str):
    """
    Returns domain age in days or None if unavailable.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        return (datetime.utcnow() - creation_date).days

    except Exception:
        return None

class URLAnalysisTool(BaseTool):
    name: str = "URL Analysis Tool"
    description: str = (
        "Analyzes URLs for phishing indicators including domain reputation, "
        "typosquatting, and suspicious structural patterns"
    )

    def _run(self, url: str) -> str:
        results = {
            'is_valid': False,
            'domain': '',
            'tld': '',
            'subdomain': '',
            'suspicious_patterns': [],
            'risk_score_raw': 0,
            'risk_score': 0
        }

        # -------------------------
        # URL validation
        # -------------------------
        if not validators.url(url):
            results['suspicious_patterns'].append('Invalid URL format')
            results['risk_score'] = 30
            return self._format_results(results)

        results['is_valid'] = True

        extracted = tldextract.extract(url)
        fqdn = f"{extracted.domain}.{extracted.suffix}"

        results['domain'] = extracted.domain
        results['tld'] = extracted.suffix
        results['subdomain'] = extracted.subdomain

        # -------------------------
        # Legitimate domain bypass
        # -------------------------
        if is_exact_legitimate_domain(
            fqdn,
            flatten_legitimate_domains(Config.LEGITIMATE_DOMAINS)
        ):
            results['suspicious_patterns'].append("Known legitimate domain")
            results['risk_score'] = 0
            return self._format_results(results)

        # =========================
        # CATEGORY 1: Domain Age
        # =========================
        domain_age_days = get_domain_age_days(fqdn)

        if domain_age_days is not None:
            if domain_age_days < 7:
                results['suspicious_patterns'].append(
                    f"Very new domain ({domain_age_days} days old)"
                )
                results['risk_score_raw'] += 40
            elif domain_age_days < 30:
                results['suspicious_patterns'].append(
                    f"Newly registered domain ({domain_age_days} days old)"
                )
                results['risk_score_raw'] += 30
            elif domain_age_days < 90:
                results['suspicious_patterns'].append(
                    f"Recently registered domain ({domain_age_days} days old)"
                )
                results['risk_score_raw'] += 15
        else:
            results['suspicious_patterns'].append("Domain age unavailable")

        # =========================
        # CATEGORY 2: URL Structure
        # =========================
        parsed = urlparse(url)

        if not url.lower().startswith("https://"):
            results['suspicious_patterns'].append("No HTTPS (unencrypted connection)")
            results['risk_score_raw'] += 10

        if len(parsed.path.strip("/")) <= 8:
            results['suspicious_patterns'].append("Short or opaque URL path")
            results['risk_score_raw'] += 10

        if parsed.query.count("&") > 3:
            results['suspicious_patterns'].append("Excessive query parameters")
            results['risk_score_raw'] += 10

        if any(char in url for char in ['@', '..', '%2f', '%3a']):
            results['suspicious_patterns'].append("URL obfuscation detected")
            results['risk_score_raw'] += 15

        if len(url) > 75:
            results['suspicious_patterns'].append("Unusually long URL")
            results['risk_score_raw'] += 10

        # =========================
        # CATEGORY 3: Subdomains
        # =========================
        if results['subdomain'] and results['subdomain'].count('.') > 2:
            results['suspicious_patterns'].append("Excessive subdomain nesting")
            results['risk_score_raw'] += 20

        # =========================
        # CATEGORY 4: Brand abuse
        # =========================
        for brand, legit_domain in Config.LEGITIMATE_DOMAINS.items():
            brand = brand.lower()
            domain_l = results['domain'].lower()
            subdomain_l = results['subdomain'].lower()

            if brand in subdomain_l and brand not in domain_l:
                results['suspicious_patterns'].append(
                    f"Brand '{brand}' used in subdomain"
                )
                results['risk_score_raw'] += 35

            if brand in domain_l:
                legit_roots = legit_domain if isinstance(legit_domain, list) else [legit_domain]
                legit_roots = [ld.split('.')[0] for ld in legit_roots]

                if domain_l not in legit_roots:
                    results['suspicious_patterns'].append(
                        f"Possible {brand} typosquatting"
                    )
                    results['risk_score_raw'] += 35

        # =========================
        # CATEGORY 5: Domain entropy
        # =========================
        if self._high_entropy_domain(results['domain']):
            results['suspicious_patterns'].append("High-entropy / random-looking domain")
            results['risk_score_raw'] += 15

        # -------------------------
        # Normalize risk score
        # -------------------------
        results['risk_score'] = min(
            int((results['risk_score_raw'] / 120) * 100),
            100
        )

        return self._format_results(results)

    # -------------------------
    # Helpers
    # -------------------------
    def _high_entropy_domain(self, domain: str) -> bool:
        if len(domain) < 10:
            return False
        vowels = sum(1 for c in domain if c in "aeiou")
        return vowels / len(domain) < 0.25

    def _format_results(self, results: Dict) -> str:
        output = "URL Analysis Results:\n"
        output += f"Valid URL: {results['is_valid']}\n"
        output += f"Domain: {results['domain']}\n"
        output += f"TLD: {results['tld']}\n"
        output += f"Subdomain: {results['subdomain']}\n"
        output += f"Risk Score: {results['risk_score']}/100\n"
        output += f"Suspicious Patterns Found: {len(results['suspicious_patterns'])}\n"
        for pattern in results['suspicious_patterns']:
            output += f"  - {pattern}\n"
        output += "\nEnd of URL Analysis.\n"
        return output

class ContentAnalysisTool(BaseTool):
    name: str = "Content Analysis Tool"
    description: str = (
        "Analyzes text content for phishing indicators including social engineering "
        "tactics, urgency signals, and linguistic anomalies"
    )

    MAX_RAW_SCORE: ClassVar[int] = 135

    def _run(self, content: str) -> str:
        """Analyze text content for phishing patterns"""

        results = {
            'suspicious_keywords_found': [],
            'urgency_phrases_found': [],
            'urgency_level': 'low',
            'contains_threats': False,
            'grammar_issues': 0,
            'risk_score_raw': 0,
            'risk_score': 0
        }

        content_lower = content.lower()

        # ----------------------------------------------------
        # 1. Suspicious keyword detection
        # ----------------------------------------------------
        for keyword in Config.SUSPICIOUS_KEYWORDS:
            if keyword in content_lower:
                results['suspicious_keywords_found'].append(keyword)
                results['risk_score_raw'] += 8

        # Cap keyword contribution
        results['risk_score_raw'] = min(results['risk_score_raw'], 30)

        # ----------------------------------------------------
        # 2. Weighted urgency detection
        # ----------------------------------------------------
        urgency_score = 0
        max_urgency_level = "low"

        for level, data in Config.URGENCY_KEYWORDS.items():
            for phrase in data["keywords"]:
                if phrase in content_lower:
                    results['urgency_phrases_found'].append(phrase)
                    urgency_score += data["weight"]

                    if level == "high":
                        max_urgency_level = "high"
                    elif level == "medium" and max_urgency_level != "high":
                        max_urgency_level = "medium"

        results['urgency_level'] = max_urgency_level
        urgency_score = min(urgency_score, 35)
        results['risk_score_raw'] += urgency_score

        # ----------------------------------------------------
        # 3. Threat detection
        # ----------------------------------------------------
        threat_words = [
            'suspend',
            'terminate',
            'close your account',
            'legal action',
            'account will be locked',
            'account will be suspended'
        ]

        if any(word in content_lower for word in threat_words):
            results['contains_threats'] = True
            results['risk_score_raw'] += 30

        # Threat + high urgency amplification
        if results['contains_threats'] and results['urgency_level'] == "high":
            results['risk_score_raw'] += 15

        # ----------------------------------------------------
        # 4. Link + urgency proximity boost
        # ----------------------------------------------------
        if results['urgency_phrases_found'] and re.search(r'https?://', content_lower):
            results['risk_score_raw'] += 10

        # ----------------------------------------------------
        # 5. Grammar issue detection
        # ----------------------------------------------------
        grammar_patterns = [
            r'\s+[a-z]',
            r'[.!?]\s*[a-z]',
        ]

        for pattern in grammar_patterns:
            results['grammar_issues'] += len(re.findall(pattern, content))

        if results['grammar_issues'] > 3:
            results['risk_score_raw'] += 15

        # ----------------------------------------------------
        # 6. Generic greeting detection
        # ----------------------------------------------------
        if re.search(r'\b(dear (customer|user|member|valued))\b', content_lower):
            results['suspicious_keywords_found'].append('generic greeting')
            results['risk_score_raw'] += 10

        # ----------------------------------------------------
        # 7. Normalize final risk score (NEW)
        # ----------------------------------------------------
        results['risk_score'] = min(
            int((results['risk_score_raw'] / self.MAX_RAW_SCORE) * 100),
            100
        )

        return self._format_results(results)

    def _format_results(self, results: Dict) -> str:
        """Format results as a string for the agent"""

        output = "Content Analysis Results:\n"
        output += f"Risk Score: {results['risk_score']}/100\n"
        output += f"Urgency Level: {results['urgency_level']}\n"
        output += f"Contains Threats: {results['contains_threats']}\n"
        output += f"Grammar Issues: {results['grammar_issues']}\n"

        output += (
            f"Urgency Phrases Found ({len(results['urgency_phrases_found'])}):\n"
        )
        for phrase in results['urgency_phrases_found']:
            output += f"  - {phrase}\n"

        output += (
            f"Suspicious Keywords Found ({len(results['suspicious_keywords_found'])}):\n"
        )
        for keyword in results['suspicious_keywords_found']:
            output += f"  - {keyword}\n"

        output += "\nEnd of Content Analysis.\n"
        return output

class VisualAnalysisTool(BaseTool):
    name: str = "Visual Analysis Tool"
    description: str = (
        "Analyzes visual and structural indicators of phishing including "
        "brand impersonation, credential harvesting, and suspicious page behavior"
    )

    MAX_RAW_SCORE: ClassVar[int] = 140

    def _run(self, url: str) -> str:
        results = {
            'brand_impersonation': [],
            'suspicious_forms': False,
            'external_resources': 0,
            'risk_score_raw': 0,
            'risk_score': 0
        }

        try:
            response = requests.get(
                url,
                timeout=6,
                headers={
                    'User-Agent': (
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    )
                }
            )
            html_content = response.text
        except Exception:
            results['risk_score_raw'] += 10
            results['risk_score'] = int((10 / self.MAX_RAW_SCORE) * 100)
            return self._format_results(results, error=True)

        soup = BeautifulSoup(html_content, 'html.parser')
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc

        # =========================
        # 1. Suspicious forms
        # =========================
        forms = soup.find_all('form')
        for form in forms:
            password_inputs = form.find_all('input', {'type': 'password'})
            email_inputs = form.find_all(
                'input', {'type': ['email', 'text']}
            )

            if password_inputs:
                results['suspicious_forms'] = True
                results['risk_score_raw'] += 25

                if email_inputs:
                    results['risk_score_raw'] += 15

                action = form.get('action', '')
                if action and action.startswith('http'):
                    if urlparse(action).netloc != base_domain:
                        results['risk_score_raw'] += 20

        # =========================
        # 2. Hidden inputs / iframes
        # =========================
        hidden_inputs = soup.find_all('input', {'type': 'hidden'})
        if hidden_inputs:
            results['risk_score_raw'] += 10

        iframes = soup.find_all('iframe')
        if iframes:
            results['risk_score_raw'] += 15

        # =========================
        # 3. External resources
        # =========================
        images = soup.find_all('img', src=True)
        scripts = soup.find_all('script', src=True)

        external_count = 0
        for element in images + scripts:
            src = element.get('src', '')
            if src.startswith('http'):
                if urlparse(src).netloc != base_domain:
                    external_count += 1

        results['external_resources'] = external_count
        if external_count > 15:
            results['risk_score_raw'] += 20
        elif external_count > 8:
            results['risk_score_raw'] += 10

        # =========================
        # 4. Brand impersonation (contextual)
        # =========================
        page_text = soup.get_text().lower()
        for brand in Config.LEGITIMATE_DOMAINS.keys():
            brand_l = brand.lower()
            if brand_l in page_text and results['suspicious_forms']:
                results['brand_impersonation'].append(brand)
                results['risk_score_raw'] += 35

        # =========================
        # 5. JavaScript redirects
        # =========================
        scripts_inline = soup.find_all('script')
        for script in scripts_inline:
            if script.string and re.search(r'window\.location|document\.location', script.string):
                results['risk_score_raw'] += 15
                break

        # -------------------------
        # Normalize score
        # -------------------------
        results['risk_score'] = min(
            int((results['risk_score_raw'] / self.MAX_RAW_SCORE) * 100),
            100
        )

        return self._format_results(results)

    def _format_results(self, results: Dict, error: bool = False) -> str:
        if error:
            return (
                "Visual Analysis Results:\n"
                "Error fetching page content.\n"
                f"Risk Score: {results['risk_score']}/100\n"
            )

        output = "Visual Analysis Results:\n"
        output += f"Risk Score: {results['risk_score']}/100\n"
        output += f"Suspicious Forms: {results['suspicious_forms']}\n"
        output += f"External Resources: {results['external_resources']}\n"
        output += f"Brand Impersonation Detected: {len(results['brand_impersonation'])}\n"
        for brand in results['brand_impersonation']:
            output += f"  - {brand}\n"
        output += "\nEnd of Visual Analysis.\n"
        return output

class VirusTotalTool(BaseTool):
    name: str = "VirusTotal Reputation Tool"
    description: str = "Checks URL or domain reputation using VirusTotal"

    MAX_ENGINES_ASSUMED: ClassVar[int] = 90

    def _run(self, indicator: str) -> str:
        import os
        import requests
        import time

        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return "VirusTotal: API key not configured"

        headers = {"x-apikey": api_key}

        # -------------------------
        # Submit URL
        # -------------------------
        submit_resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": indicator},
            timeout=10
        )

        if submit_resp.status_code != 200:
            return "VirusTotal: URL submission failed"

        analysis_id = submit_resp.json().get("data", {}).get("id")
        if not analysis_id:
            return "VirusTotal: Failed to obtain analysis ID"

        # -------------------------
        # Poll analysis (short)
        # -------------------------
        for _ in range(3):
            time.sleep(1)
            analysis_resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10
            )
            if analysis_resp.status_code == 200:
                break
        else:
            return "VirusTotal: Analysis still pending"

        stats = (
            analysis_resp.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats")
        )

        if not stats:
            return "VirusTotal: Analysis pending — no verdict available"

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total = malicious + suspicious + harmless + undetected

        # -------------------------
        # Risk normalization
        # -------------------------
        if malicious >= 10:
            risk_score = 100
            verdict = "confirmed malicious"
        elif malicious >= 5:
            risk_score = 80
            verdict = "highly likely malicious"
        elif malicious >= 1:
            risk_score = 60
            verdict = "likely malicious"
        elif suspicious >= 5:
            risk_score = 50
            verdict = "suspicious"
        elif suspicious >= 1:
            risk_score = 30
            verdict = "weakly suspicious"
        else:
            risk_score = 0
            verdict = "no detections (inconclusive)"

        # -------------------------
        # Evidence
        # -------------------------
        evidence = [
            f"VirusTotal Verdict: {verdict}",
            f"Risk Score: {risk_score}/100",
            f"Detections: malicious={malicious}, suspicious={suspicious}, total_engines={total}"
        ]

        return "\n".join(evidence)

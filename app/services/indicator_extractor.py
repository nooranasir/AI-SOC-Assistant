"""Indicator extraction helpers.

Purpose:
    Extract IP addresses, domains, and file hashes from alert and log text so
    external security services can enrich the analysis pipeline.

Inputs:
    Free-form text.

Outputs:
    Normalized indicator lists.

Dependencies:
    re and ipaddress from the Python standard library.
"""

from collections.abc import Iterable
import ipaddress
import re


class IndicatorExtractor:
    """Extract common threat indicators from text."""

    _hash_pattern = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
    _domain_pattern = re.compile(
        r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    )
    _ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _url_pattern = re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]+")
    _username_keywords_pattern = re.compile(
        r"\b(?:user(?:name)?|account|login)\b\s*[:=]\s*['\"]?([a-zA-Z0-9._-]+)['\"]?|\b(?:user|account)\s+(['\"]?)([a-zA-Z0-9._-]+)\2\b",
        re.IGNORECASE
    )
    _email_pattern = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    _domain_user_pattern = re.compile(r"\b[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+\b")

    def extract_ips(self, text: str) -> list[str]:
        """Extract valid IPv4 addresses from text."""
        candidate_ips = self._ip_pattern.findall(text)
        valid_ips: list[str] = []
        for candidate_ip in candidate_ips:
            try:
                ipaddress.ip_address(candidate_ip)
            except ValueError:
                continue
            valid_ips.append(candidate_ip)
        return self._deduplicate(valid_ips)

    def extract_domains(self, text: str) -> list[str]:
        """Extract domains from text while filtering out IP addresses and common file names."""
        domains = [domain.lower() for domain in self._domain_pattern.findall(text)]
        
        # Also parse domains from URLs directly to be safe
        from urllib.parse import urlparse
        for url in self.extract_urls(text):
            try:
                parsed = urlparse(url)
                netloc = parsed.netloc.split(":")[0]  # strip port if present
                if netloc:
                    domains.append(netloc.lower())
            except Exception:
                continue

        # Exclude extensions that represent files rather than valid TLDs
        file_extensions = {".exe", ".dll", ".bin", ".zip", ".tmp", ".msi", ".sys", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".log", ".txt", ".json", ".xml", ".yaml", ".yml", ".bat", ".sh", ".cmd"}
        valid_domains = []
        for domain in domains:
            if any(domain.endswith(ext) for ext in file_extensions):
                continue
            valid_domains.append(domain)

        ip_set = set(self.extract_ips(text))
        return self._deduplicate([d for d in valid_domains if d not in ip_set])

    def extract_hashes(self, text: str) -> list[str]:
        """Extract MD5, SHA1, and SHA256 hashes from text."""
        return self._deduplicate(match.lower() for match in self._hash_pattern.findall(text))

    def extract_urls(self, text: str) -> list[str]:
        """Extract valid HTTP/HTTPS URLs from text."""
        return self._deduplicate(self._url_pattern.findall(text))

    def extract_usernames(self, text: str) -> list[str]:
        """Extract potential usernames from text based on common patterns."""
        usernames: list[str] = []
        
        # 1. Matches like "user: admin", "username=guest", "account='test'"
        for match in self._username_keywords_pattern.finditer(text):
            val = match.group(1) or match.group(3)
            if val:
                usernames.append(val.strip())
                
        # 2. Matches email addresses (e.g. admin@company.com)
        usernames.extend(self._email_pattern.findall(text))
        
        # 3. Matches domain/user (e.g. CONTOSO\Administrator)
        usernames.extend(self._domain_user_pattern.findall(text))
        
        # Filter out common false positives
        false_positives = {"to", "a", "the", "by", "from", "on", "in", "at", "for"}
        filtered = [u for u in usernames if u.lower() not in false_positives]
        
        return self._deduplicate(filtered)

    def _deduplicate(self, values: Iterable[str]) -> list[str]:
        """Return values in their original order without duplicates."""
        seen: set[str] = set()
        ordered_values: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            ordered_values.append(value)
        return ordered_values
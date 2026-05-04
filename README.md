Template name:
Django Security Container (HTTPS) — Murzagalieva

Usage:
Generates a web interface for URL and content filtering against malicious code injection via ads, services, and user content. 
All communication is enforced over HTTPS. Enter a URL (only https:// allowed) and HTML content, then click "Проверить" to analyze. 
Edit BLACKLIST_DOMAINS, SUSPICIOUS_PATTERNS, and SHORT_LINK_SERVICES in filter_logic.py to customize filtering rules. 
HTTP requests are automatically redirected to HTTPS, and URLs with http:// protocol are blocked at the interface level with a validation tooltip.

License:
Academic Free License v. 3.0

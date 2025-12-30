"""
OutputGuard - LLM Response Sanitization
========================================
Protects against:
- Sensitive Data Leakage (passwords, API keys, tokens)
- Infrastructure Exposure (internal IPs)
- Hallucination Detection
"""

import re
from datetime import datetime
from typing import Tuple, List
from dataclasses import dataclass


@dataclass
class SanitizationResult:
    """Result of output sanitization."""
    sanitized_text: str
    redactions_made: int
    hallucination_risk: bool
    redaction_details: List[str]


class OutputGuard:
    """
    Advanced OutputGuard for sanitizing LLM responses.
    
    Features:
    - Credential and key redaction
    - Internal IP address masking
    - Hallucination risk detection
    """
    
    # ==================== SENSITIVE DATA PATTERNS ====================
    
    SENSITIVE_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
        # Credentials
        ("PASSWORD", re.compile(
            r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
            re.IGNORECASE
        ), "password = [REDACTED]"),
        
        # Generic API Keys
        ("API_KEY", re.compile(
            r"(?i)(api[_-]?key|apikey|api[_-]?secret|access[_-]?key|secret[_-]?key)\s*[:=]\s*[\w\-]+",
            re.IGNORECASE
        ), "api_key = [REDACTED]"),
        
        # AWS Access Keys (AKIA pattern)
        ("AWS_KEY", re.compile(
            r"AKIA[0-9A-Z]{16}",
        ), "[AWS_KEY_REDACTED]"),
        
        # AWS Secret Keys
        ("AWS_SECRET", re.compile(
            r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*[\w/+=]+",
            re.IGNORECASE
        ), "aws_secret = [REDACTED]"),
        
        # Private Keys (RSA, DSA, EC)
        ("PRIVATE_KEY", re.compile(
            r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.IGNORECASE
        ), "[PRIVATE_KEY_REDACTED]"),
        
        # JWT Tokens
        ("JWT_TOKEN", re.compile(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        ), "[JWT_TOKEN_REDACTED]"),
        
        # Bearer Tokens
        ("BEARER_TOKEN", re.compile(
            r"(?i)bearer\s+[a-zA-Z0-9\-_\.]+",
            re.IGNORECASE
        ), "Bearer [TOKEN_REDACTED]"),
        
        # GitHub Tokens
        ("GITHUB_TOKEN", re.compile(
            r"gh[pousr]_[A-Za-z0-9_]{36,}",
        ), "[GITHUB_TOKEN_REDACTED]"),
        
        # Google API Keys
        ("GOOGLE_API_KEY", re.compile(
            r"AIza[0-9A-Za-z\-_]{35}",
        ), "[GOOGLE_API_KEY_REDACTED]"),
        
        # Slack Tokens
        ("SLACK_TOKEN", re.compile(
            r"xox[baprs]-[0-9A-Za-z\-]+",
        ), "[SLACK_TOKEN_REDACTED]"),
        
        # Database Connection Strings
        ("DB_CONNECTION", re.compile(
            r"(?i)(mongodb|postgresql|mysql|redis)://[^\s]+",
            re.IGNORECASE
        ), "[DATABASE_URL_REDACTED]"),
        
        # SSH Private Key Content
        ("SSH_KEY_CONTENT", re.compile(
            r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
        ), "[SSH_KEY_REDACTED]"),
    ]
    
    # Internal IP Addresses
    IP_INTERNAL_PATTERN = re.compile(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
    )
    
    # Localhost patterns
    LOCALHOST_PATTERN = re.compile(
        r"\b(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|0\.0\.0\.0)\b"
    )
    
    # ==================== HALLUCINATION INDICATORS ====================
    
    WEAK_CONFIDENCE_PHRASES: List[str] = [
        "i think",
        "i believe", 
        "probably",
        "maybe",
        "might be",
        "could be",
        "it seems",
        "appears to be",
        "i'm not sure",
        "i'm uncertain",
        "possibly",
        "presumably",
        "i assume",
        "speculating",
    ]
    
    def __init__(self, 
                 redact_internal_ips: bool = True,
                 redact_localhost: bool = False,
                 log_events: bool = True):
        """
        Initialize OutputGuard.
        
        Args:
            redact_internal_ips: Whether to redact internal IP addresses
            redact_localhost: Whether to redact localhost references
            log_events: Whether to log security events
        """
        self.redact_internal_ips = redact_internal_ips
        self.redact_localhost = redact_localhost
        self.log_events = log_events
    
    def sanitize(self, response: str) -> str:
        """
        Sanitizes LLM output by removing sensitive information.
        
        Args:
            response: Raw LLM response
            
        Returns:
            Sanitized response string
        """
        if not response:
            return ""
        
        result = self.sanitize_detailed(response)
        return result.sanitized_text
    
    def sanitize_detailed(self, response: str) -> SanitizationResult:
        """
        Sanitizes LLM output and returns detailed results.
        
        Args:
            response: Raw LLM response
            
        Returns:
            SanitizationResult with sanitized text and metadata
        """
        if not response:
            return SanitizationResult(
                sanitized_text="",
                redactions_made=0,
                hallucination_risk=False,
                redaction_details=[]
            )
        
        sanitized = response
        redactions = 0
        details = []
        
        # Apply all sensitive data patterns
        for pattern_name, pattern, replacement in self.SENSITIVE_PATTERNS:
            matches = pattern.findall(sanitized)
            if matches:
                count = len(matches) if isinstance(matches[0], str) else len(matches)
                sanitized = pattern.sub(replacement, sanitized)
                redactions += count
                details.append(f"{pattern_name}: {count} redacted")
                self._log_security_event("DATA_REDACTION", f"{pattern_name}: {count} instances")
        
        # Redact internal IP addresses
        if self.redact_internal_ips:
            internal_ips = self.IP_INTERNAL_PATTERN.findall(sanitized)
            if internal_ips:
                sanitized = self.IP_INTERNAL_PATTERN.sub("[INTERNAL_IP_REDACTED]", sanitized)
                redactions += len(internal_ips)
                details.append(f"INTERNAL_IP: {len(internal_ips)} redacted")
                self._log_security_event("IP_REDACTION", f"{len(internal_ips)} internal IPs")
        
        # Optionally redact localhost
        if self.redact_localhost:
            localhost_matches = self.LOCALHOST_PATTERN.findall(sanitized)
            if localhost_matches:
                sanitized = self.LOCALHOST_PATTERN.sub("[LOCALHOST_REDACTED]", sanitized)
                redactions += len(localhost_matches)
                details.append(f"LOCALHOST: {len(localhost_matches)} redacted")
        
        # Check for hallucination risk
        hallucination_risk = self._detect_hallucination_risk(response)
        
        return SanitizationResult(
            sanitized_text=sanitized,
            redactions_made=redactions,
            hallucination_risk=hallucination_risk,
            redaction_details=details
        )
    
    def _detect_hallucination_risk(self, response: str) -> bool:
        """
        Detects potential hallucinations based on weak confidence phrases.
        
        Args:
            response: The response to analyze
            
        Returns:
            True if hallucination risk detected
        """
        lower_response = response.lower()
        
        for phrase in self.WEAK_CONFIDENCE_PHRASES:
            if phrase in lower_response:
                self._log_security_event("HALLUCINATION_RISK", f"Weak confidence: '{phrase}'")
                return True
        
        return False
    
    def _log_security_event(self, event_type: str, details: str) -> None:
        """
        Log security events for monitoring.
        
        Args:
            event_type: Type of event
            details: Event details
        """
        if self.log_events:
            timestamp = datetime.now().isoformat()
            print(f"[OUTPUT GUARD] [{timestamp}] Type: {event_type} | Details: {details}")
            # In production: send to monitoring system
    
    def has_sensitive_data(self, response: str) -> bool:
        """
        Quick check if response contains sensitive data.
        
        Args:
            response: Response to check
            
        Returns:
            True if sensitive data detected
        """
        if not response:
            return False
        
        # Check all patterns
        for _, pattern, _ in self.SENSITIVE_PATTERNS:
            if pattern.search(response):
                return True
        
        # Check internal IPs
        if self.redact_internal_ips and self.IP_INTERNAL_PATTERN.search(response):
            return True
        
        return False

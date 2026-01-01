"""
InputGuard - Multi-Layered Prompt Injection Detection
======================================================
Protects against:
- Prompt Injection Attacks
- Jailbreak Attempts  
- Command/SQL Injection
- Encoding/Obfuscation Attacks
"""

import re
from datetime import datetime
from typing import List, Tuple
from .exceptions import PromptInjectionException, StructuralViolationException
import difflib


class InputGuard:
    """
    Advanced InputGuard with multi-layered prompt injection detection.
    
    Layers:
    1. Blacklist keyword detection
    2. Regex pattern matching for sophisticated attacks
    3. Structural validation (length, special chars, repetition)
    """
    
    # ==================== LAYER 1: BLACKLIST KEYWORDS ====================
    BLACKLIST_KEYWORDS: List[str] = [
        # Prompt Override Attacks
        "ignore previous instructions",
        "ignore all instructions",
        "ignore above",
        "disregard previous",
        "forget everything",
        "new instructions",
        "override instructions",
        "cancel previous",
        "reset instructions",
        
        # System Manipulation
        "you are now",
        "you are a hacked",
        "system prompt",
        "reveal your prompt",
        "show your instructions",
        "what are your guidelines",
        "print your rules",
        "display your configuration",
        "tell me your instructions",
        
        # Jailbreak Attempts
        "pretend you are",
        "roleplay as",
        "act as if",
        "simulate being",
        "hypothetically",
        "dan mode",
        "developer mode",
        "god mode",
        "jailbreak",
        "bypass restrictions",
        "ignore safety",
        
        # Command/SQL Injection
        "drop table",
        "delete from",
        "insert into",
        "'; drop",
        "union select",
        "exec(",
        "execute(",
        "xp_cmdshell",
        "--comment",
        
        # Encoding/Obfuscation Detection
        "base64 decode",
        "hex encode",
        "rot13",
        "url encode",
        "decode this",
    ]
    
    # ==================== LAYER 2: REGEX PATTERNS ====================
    MALICIOUS_PATTERNS: List[Tuple[str, re.Pattern]] = [
        # Instruction Override Patterns
        ("INSTRUCTION_OVERRIDE", re.compile(
            r"(?i)\b(ignore|disregard|forget|skip|bypass)\s+(all|previous|above|prior|my|every)\s+(instructions?|rules?|guidelines?|commands?|restrictions?)",
            re.IGNORECASE
        )),
        ("NEW_INSTRUCTIONS", re.compile(
            r"(?i)\b(new|updated|revised|real|actual)\s+(instructions?|rules?|system\s+prompt)",
            re.IGNORECASE
        )),
        
        # Role Manipulation
        ("ROLE_MANIPULATION", re.compile(
            r"(?i)(you\s+are\s+now|act\s+as|pretend\s+to\s+be|simulate\s+being|behave\s+like|become)\s+\w+",
            re.IGNORECASE
        )),
        ("JAILBREAK_MODE", re.compile(
            r"(?i)(jailbreak|dan\s+mode|developer\s+mode|god\s+mode|unrestricted\s+mode|evil\s+mode)",
            re.IGNORECASE
        )),
        
        # Prompt Leakage Attempts
        ("PROMPT_LEAKAGE", re.compile(
            r"(?i)(show|reveal|display|print|output|repeat|echo)\s+(your|the|my)?\s*(prompt|instructions?|system\s+message|guidelines?|rules?|configuration)",
            re.IGNORECASE
        )),
        
        # SQL/Command Injection Signatures
        ("SQL_INJECTION", re.compile(
            r"(?i)(drop|delete|insert|update|truncate)\s+(table|from|into)",
            re.IGNORECASE
        )),
        ("SQL_UNION", re.compile(
            r"(?i)(union|concat)\s+select",
            re.IGNORECASE
        )),
        ("SQL_INLINE", re.compile(
            r"(?i);\s*(drop|delete|exec|execute|insert)",
            re.IGNORECASE
        )),
        
        # Suspicious Character Patterns (potential encoding)
        ("URL_ENCODING", re.compile(
            r"(%[0-9A-Fa-f]{2}){5,}"  # 5+ consecutive URL encoded chars
        )),
        ("HEX_ENCODING", re.compile(
            r"(\\x[0-9A-Fa-f]{2}){5,}"  # 5+ consecutive hex escape sequences
        )),
        ("BASE64_SUSPICIOUS", re.compile(
            r"[A-Za-z0-9+/]{40,}={0,2}"  # Long Base64-like strings (40+ chars)
        )),
        
        # Context Escape Attempts
        ("CONTEXT_ESCAPE", re.compile(
            r"(?i)(end\s+of\s+context|context\s+ends?|stop\s+context|exit\s+context)",
            re.IGNORECASE
        )),
    ]
    
    # ==================== LAYER 3: STRUCTURAL LIMITS ====================
    MAX_PROMPT_LENGTH: int = 2000
    MAX_SPECIAL_CHARS_RATIO: int = 30  # 30% max special characters
    MAX_CONSECUTIVE_REPEAT: int = 9  # 10+ consecutive identical chars is suspicious
    
    def __init__(self, 
                 max_length: int = None,
                 max_special_ratio: int = None,
                 log_events: bool = True):
        """
        Initialize InputGuard with optional custom thresholds.
        
        Args:
            max_length: Maximum allowed prompt length
            max_special_ratio: Maximum percentage of special characters
            log_events: Whether to log security events
        """
        if max_length:
            self.MAX_PROMPT_LENGTH = max_length
        if max_special_ratio:
            self.MAX_SPECIAL_CHARS_RATIO = max_special_ratio
        self.log_events = log_events
    
    def validate(self, prompt: str) -> bool:
        """
        Validates input prompt using multi-layer security checks.
        
        Args:
            prompt: User input to validate
            
        Returns:
            True if validation passes
            
        Raises:
            PromptInjectionException: If malicious content detected
            StructuralViolationException: If structural anomalies detected
            ValueError: If input is invalid (empty/None)
        """
        # Basic validation
        if prompt is None or not prompt.strip():
            raise ValueError("Prompt cannot be empty")
        
        user_input = prompt.strip()
        
        # Layer 0: Length validation (prevent resource exhaustion)
        if len(user_input) > self.MAX_PROMPT_LENGTH:
            self._log_security_event("LENGTH_EXCEEDED", f"{len(user_input)} chars")
            raise StructuralViolationException(
                message=f"Prompt exceeds maximum length ({self.MAX_PROMPT_LENGTH} chars)",
                details=f"Received {len(user_input)} characters"
            )
        
        self._check_blacklist(user_input)
        self._check_fuzzy_blacklist(user_input) # New Fuzzy Layer
        self._check_regex_patterns(user_input)
        self._check_structural_integrity(user_input)
        return True

    def _check_blacklist(self, text: str) -> None:
        """Layer 1: Exact Blacklist Matching"""
        text_lower = text.lower()
        for keyword in self.BLACKLIST_KEYWORDS:
            if keyword in text_lower:
                self._log_security_event("BLACKLIST_MATCH", f"Blocked keyword: {keyword}")
                raise PromptInjectionException(f"Security Alert: Blocked content detected ({keyword}).")

    def _check_fuzzy_blacklist(self, text: str) -> None:
        """Layer 1.5: Fuzzy Blacklist Matching (e.g., 'sustem' vs 'system')"""
        text_lower = text.lower()
        words = text_lower.split()
        
        # Check against single-word blacklist items for efficiency mostly, 
        # but for simplicity we check against all blacklist items that are short phrases too.
        # Threshold 0.85 means 'sustem' (5/6 matches) = 0.83? No.
        # sustem vs system: matching 's' 't' 'e' 'm' + 'u'/'y'. 5/6 = 0.833. 
        # let's set threshold to 0.80 for strict but catching typos.
        
        # Let's use a specialized list for fuzzy checking to avoid noise
        # NOTE: Removed "bypass" - too many false positives for educational security questions
        #       like "how do attackers bypass antivirus?"
        FUZZY_TARGETS = [
            "jailbreak"  # Only truly dangerous isolated terms
        ]
        
        # These terms are only suspicious in specific contexts (instruction manipulation)
        # Not when used in educational cybersecurity questions
        CONTEXT_SENSITIVE_TERMS = ["system", "prompt", "instruct", "ignore", "rule", "guideline"]
        
        for word in words:
            # Check dangerous isolated terms
            matches = difflib.get_close_matches(word, FUZZY_TARGETS, n=1, cutoff=0.8)
            if matches:
                matched_term = matches[0]
                self._log_security_event("FUZZY_MATCH", f"Suspicious term detected: '{word}' (similar to '{matched_term}')")
                raise PromptInjectionException(f"Security Alert: Suspicious terminology detected ('{word}').")

    def _check_regex_patterns(self, text: str) -> None:
        """Layer 2: Regex Pattern Matching"""
        for pattern_name, pattern in self.MALICIOUS_PATTERNS:
            if pattern.search(text):
                self._log_security_event("PATTERN_MATCH", pattern_name)
                raise PromptInjectionException(
                    message="Suspicious pattern detected",
                    details=f"Pattern type: {pattern_name}"
                )
        
        # Layer 3: Structural analysis
        # self._check_structural_integrity(text) # Already called in validate()
        
        return True
    
    def _check_structural_integrity(self, prompt: str) -> None:
        """
        Analyzes prompt structure for anomalies.
        
        Args:
            prompt: The prompt to analyze
            
        Raises:
            StructuralViolationException: If structural anomalies detected
        """
        # Check for excessive special characters (potential encoding/obfuscation)
        special_char_count = sum(
            1 for c in prompt 
            if not c.isalnum() and not c.isspace()
        )
        special_char_percentage = int((special_char_count * 100) / len(prompt))
        
        if special_char_percentage > self.MAX_SPECIAL_CHARS_RATIO:
            self._log_security_event("SPECIAL_CHARS", f"{special_char_percentage}%")
            raise StructuralViolationException(
                message="Excessive special characters detected (potential encoding attack)",
                details=f"{special_char_percentage}% special characters"
            )
        
        # Check for suspicious repetition (potential buffer overflow or fuzzing)
        if self._has_excessive_repetition(prompt):
            self._log_security_event("REPETITION", "Excessive character repetition")
            raise StructuralViolationException(
                message="Suspicious input pattern detected",
                details="Excessive character repetition"
            )
    
    def _has_excessive_repetition(self, prompt: str) -> bool:
        """
        Detects excessive character repetition.
        
        Args:
            prompt: The prompt to check
            
        Returns:
            True if excessive repetition detected
        """
        # Check for 10+ consecutive identical characters
        pattern = re.compile(r"(.)\1{" + str(self.MAX_CONSECUTIVE_REPEAT) + r",}")
        return bool(pattern.search(prompt))
    
    def _log_security_event(self, detection_type: str, details: str) -> None:
        """
        Log security events for monitoring and analysis.
        
        Args:
            detection_type: Type of detection (e.g., KEYWORD_BLACKLIST)
            details: Additional details about the detection
        """
        if self.log_events:
            timestamp = datetime.now().isoformat()
            print(f"[SECURITY ALERT] [{timestamp}] Type: {detection_type} | Details: {details}")
            # In production: send to SIEM, logging service, or security dashboard
    
    def is_safe(self, prompt: str) -> bool:
        """
        Non-raising version of validate. Returns boolean.
        
        Args:
            prompt: User input to check
            
        Returns:
            True if safe, False if potentially malicious
        """
        try:
            self.validate(prompt)
            return True
        except (PromptInjectionException, StructuralViolationException, ValueError):
            return False

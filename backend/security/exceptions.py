"""
Custom Security Exceptions
==========================
Specialized exceptions for different security violation types.
"""


class SecurityException(Exception):
    """Base exception for all security violations."""
    
    def __init__(self, message: str, detection_type: str = "GENERIC", details: str = ""):
        self.message = message
        self.detection_type = detection_type
        self.details = details
        super().__init__(self.message)
    
    def __str__(self) -> str:
        return f"[{self.detection_type}] {self.message}"


class PromptInjectionException(SecurityException):
    """Raised when prompt injection attempt is detected."""
    
    def __init__(self, message: str = "Prompt injection attempt detected", details: str = ""):
        super().__init__(message, detection_type="PROMPT_INJECTION", details=details)


class StructuralViolationException(SecurityException):
    """Raised when structural anomalies are detected in the input."""
    
    def __init__(self, message: str = "Structural violation detected", details: str = ""):
        super().__init__(message, detection_type="STRUCTURAL_VIOLATION", details=details)

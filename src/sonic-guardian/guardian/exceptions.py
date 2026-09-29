"""Custom exception types for SONiC Guardian"""


class GuardianException(Exception):
    """Base exception for all Guardian errors"""

    pass


class ConfigError(GuardianException):
    """Configuration error"""

    pass


class ScanError(GuardianException):
    """Vulnerability scanning error"""

    pass


class RemediationError(GuardianException):
    """Package remediation error"""

    pass


class ValidationError(GuardianException):
    """Health check validation error"""

    pass


class RollbackError(GuardianException):
    """Rollback operation error"""

    pass


class MetadataError(GuardianException):
    """Metadata file operation error"""

    pass


class IntelligenceServiceError(GuardianException):
    """Security Intelligence Service communication error"""

    pass

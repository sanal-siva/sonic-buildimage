"""Custom exception types for SONiC Smart Patch"""


class SmartPatchException(Exception):
    """Base exception for all Smart Patch errors"""

    pass


class ConfigError(SmartPatchException):
    """Configuration error"""

    pass


class ScanError(SmartPatchException):
    """Vulnerability scanning error"""

    pass


class RemediationError(SmartPatchException):
    """Package remediation error"""

    pass


class ValidationError(SmartPatchException):
    """Health check validation error"""

    pass


class RollbackError(SmartPatchException):
    """Rollback operation error"""

    pass


class MetadataError(SmartPatchException):
    """Metadata file operation error"""

    pass


class IntelligenceServiceError(SmartPatchException):
    """Security Intelligence Service communication error"""

    pass

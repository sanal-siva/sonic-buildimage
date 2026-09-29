"""Security Intelligence Service client integration"""

import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import requests

from guardian.models import Recommendation, VulnerabilitySeverity
from guardian.exceptions import IntelligenceServiceError
from guardian.logging import setup_logging

logger = setup_logging(__name__)


class IntelligenceServiceClient:
    """REST client for Security Intelligence Service communication"""

    def __init__(self, service_url: str, auth_token: str):
        """Initialize Intelligence Service client

        Args:
            service_url: Base URL of Intelligence Service
            auth_token: Authentication token for API requests
        """
        self.service_url = service_url
        self.auth_token = auth_token
        self.cache = {}
        self.cache_ttl = timedelta(hours=24)
        self.consecutive_failures = 0
        self.max_failures = 5
        self.circuit_breaker_cooldown = 300  # 5 minutes

    def assess_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        sonic_version: str,
        device_context: Optional[Dict[str, Any]] = None,
    ) -> List[Recommendation]:
        """Request risk assessment for discovered vulnerabilities

        Args:
            vulnerabilities: List of discovered CVEs
            sonic_version: SONiC version string
            device_context: Optional device metadata

        Returns:
            List of recommendations from Intelligence Service

        Raises:
            IntelligenceServiceError: If service unavailable
        """
        if self.consecutive_failures >= self.max_failures:
            logger.warning("Circuit breaker open - using fallback assessment")
            return self._fallback_assessment(vulnerabilities)

        try:
            # Check cache first
            cache_key = self._cache_key(vulnerabilities)
            if cache_key in self.cache:
                cached_data = self.cache[cache_key]
                if datetime.utcnow() < cached_data["expires"]:
                    logger.debug(f"Cache hit for {len(vulnerabilities)} CVEs")
                    return cached_data["recommendations"]
                else:
                    del self.cache[cache_key]

            # Prepare batch request
            request_body = {
                "vulnerabilities": vulnerabilities,
                "sonic_version": sonic_version,
                "device_context": device_context or {},
            }

            # Send request to Intelligence Service
            response = requests.post(
                f"{self.service_url}/api/v1/assess-vulnerabilities",
                json=request_body,
                headers={
                    "Authorization": f"Bearer {self.auth_token}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )

            response.raise_for_status()
            response_data = response.json()

            # Parse recommendations
            recommendations = self._parse_recommendations(response_data)

            # Cache results
            self.cache[cache_key] = {
                "recommendations": recommendations,
                "expires": datetime.utcnow() + self.cache_ttl,
            }

            self.consecutive_failures = 0
            logger.info(f"Assessment received for {len(vulnerabilities)} CVEs")
            return recommendations
        except Exception as e:
            logger.error(f"Intelligence Service error: {e}")
            self.consecutive_failures += 1
            return self._fallback_assessment(vulnerabilities)

    def _fallback_assessment(self, vulnerabilities: List[Dict[str, Any]]) -> List[Recommendation]:
        """Generate conservative recommendations when service unavailable

        Args:
            vulnerabilities: List of CVEs

        Returns:
            Fallback recommendations based on CVSS scores
        """
        recommendations = []
        for vuln in vulnerabilities:
            cvss = vuln.get("cvss_score", 0)
            severity = self._severity_from_cvss(cvss)

            if cvss >= 9.0:
                action_type = "maintenance_window"
                confidence = 0.6
            elif cvss >= 7.0:
                action_type = "auto_heal"
                confidence = 0.5
            else:
                action_type = "defer"
                confidence = 0.4

            recommendation = Recommendation(
                cve_id=vuln.get("cve_id", "UNKNOWN"),
                package_name=vuln.get("package_name", "unknown"),
                risk_score=min(cvss, 10.0),
                action_type=action_type,
                confidence=confidence,
                expected_downtime_minutes=5 if action_type == "maintenance_window" else 0,
                assessed_at=datetime.utcnow().isoformat() + "Z",
                rationale="Fallback assessment (service unavailable)",
            )
            recommendations.append(recommendation)

        logger.warning(f"Using fallback assessment for {len(vulnerabilities)} CVEs")
        return recommendations

    def _parse_recommendations(self, response_data: Dict[str, Any]) -> List[Recommendation]:
        """Parse Intelligence Service response into recommendations

        Args:
            response_data: JSON response from service

        Returns:
            List of Recommendation objects
        """
        recommendations = []
        for rec_data in response_data.get("recommendations", []):
            try:
                recommendation = Recommendation(
                    cve_id=rec_data.get("cve_id"),
                    package_name=rec_data.get("package_name"),
                    risk_score=float(rec_data.get("risk_score", 5.0)),
                    action_type=rec_data.get("action_type", "defer"),
                    confidence=float(rec_data.get("confidence", 0.5)),
                    expected_downtime_minutes=int(
                        rec_data.get("expected_downtime_minutes", 0)
                    ),
                    assessed_at=rec_data.get("assessed_at", datetime.utcnow().isoformat() + "Z"),
                    rationale=rec_data.get(
                        "rationale", "Assessment from Intelligence Service"
                    ),
                )
                recommendations.append(recommendation)
            except Exception as e:
                logger.warning(f"Failed to parse recommendation: {e}")

        return recommendations

    def _cache_key(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate cache key for vulnerability list

        Args:
            vulnerabilities: List of CVEs

        Returns:
            Cache key string
        """
        cve_ids = sorted([v.get("cve_id", "") for v in vulnerabilities])
        return "|".join(cve_ids)

    def _severity_from_cvss(self, cvss_score: float) -> VulnerabilitySeverity:
        """Map CVSS score to severity"""
        if cvss_score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        elif cvss_score >= 7.0:
            return VulnerabilitySeverity.HIGH
        elif cvss_score >= 4.0:
            return VulnerabilitySeverity.MEDIUM
        else:
            return VulnerabilitySeverity.LOW

"""Legacy explicit-assessment client; new agents use durable inventory sync.

Errors remain errors. No fallback may authorize a fix or suppress a finding.
"""
import time
import requests
from smart_patch.collector import digest
from smart_patch.exceptions import IntelligenceServiceError


class IntelligenceServiceClient:
    def __init__(self, service_url, auth_token, ca_bundle=True):
        if not service_url.startswith("https://"):
            raise ValueError("Verified HTTPS is required")
        self.url = service_url.rstrip("/")
        if not self.url.endswith("/api/v1"):
            self.url += "/api/v1"
        self.token, self.ca_bundle = auth_token, ca_bundle
        self.failures = 0
        self.retry_after = 0
        self.session = requests.Session()

    def assess_vulnerabilities(self, vulnerabilities, sonic_version, device_context=None):
        if time.monotonic() < self.retry_after:
            raise IntelligenceServiceError("Assessment unavailable; previous results remain stale")
        body={"vulnerabilities":vulnerabilities, "sonic_version":sonic_version,"device_context":device_context or {}}
        try:
            response=self.session.post(self.url+"/assess-vulnerabilities",json=body,headers={"Authorization":"Bearer "+self.token},timeout=(5,30),verify=self.ca_bundle,allow_redirects=False)
            response.raise_for_status()
            result=response.json()
            self.failures=0
            return result
        except requests.RequestException as error:
            self.failures+=1
            self.retry_after=time.monotonic()+min(300,2**min(self.failures,8))
            raise IntelligenceServiceError("Remote assessment failed; no verdict inferred") from error

    def _cache_key(self, vulnerabilities, sonic_version=None, device_context=None):
        return digest({"findings":vulnerabilities,"version":sonic_version,"context":device_context})

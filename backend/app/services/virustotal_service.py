import logging
import re
from typing import Dict, Any

import requests

from backend.app.config.settings import settings

logger = logging.getLogger("threatlens.virustotal")


class VirusTotalService:

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.timeout = 10

    def _error_result(
        self,
        status: str,
        message: str,
    ) -> Dict[str, Any]:

        return {
            "used_fallback": True,
            "status": status,
            "positives": 0,
            "total_engines": 0,
            "permalink": None,
            "scans": None,
            "message": message,
        }

    def query_file_hash(
        self,
        sha256_hash: str,
    ) -> Dict[str, Any]:

        """
        Looks up a SHA-256 hash using VirusTotal API v3.

        This method only queries the hash.
        It never uploads the user's file.
        """

        # 1. Validate SHA-256 hash
        if (
            not isinstance(sha256_hash, str)
            or not re.fullmatch(
                r"[a-fA-F0-9]{64}",
                sha256_hash.strip(),
            )
        ):
            logger.warning("Invalid SHA-256 hash supplied.")

            return self._error_result(
                "INVALID_HASH",
                "A valid SHA-256 hash is required.",
            )

        sha256_hash = sha256_hash.strip().lower()

        # 2. Check API key
        if not self.api_key or not self.api_key.strip():

            logger.info(
                "VirusTotal API key is not configured."
            )

            return self._error_result(
                "API_KEY_NOT_CONFIGURED",
                "VirusTotal API key is not configured.",
            )

        headers = {
            "x-apikey": self.api_key.strip(),
            "Accept": "application/json",
        }

        url = f"{self.base_url}/files/{sha256_hash}"

        try:

            # 3. Query VirusTotal
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
            )

            # 4. Successful response
            if response.status_code == 200:

                try:
                    data = response.json()

                except ValueError:

                    logger.error(
                        "VirusTotal returned invalid JSON."
                    )

                    return self._error_result(
                        "INVALID_RESPONSE",
                        "VirusTotal returned an invalid response.",
                    )

                attributes = (
                    data.get("data", {}).get("attributes", {})
                    if isinstance(data, dict)
                    else {}
                )

                if not isinstance(attributes, dict):
                    return self._error_result(
                        "INVALID_RESPONSE",
                        "VirusTotal response structure is invalid.",
                    )

                stats = attributes.get("last_analysis_stats")

                # No analysis statistics means no conclusive result
                if not isinstance(stats, dict) or not stats:

                    return self._error_result(
                        "ANALYSIS_UNAVAILABLE",
                        "VirusTotal has no usable analysis statistics.",
                    )

                try:

                    malicious = int(stats.get("malicious", 0))
                    suspicious = int(stats.get("suspicious", 0))

                    total = sum(
                        int(value)
                        for value in stats.values()
                    )

                except (TypeError, ValueError):

                    return self._error_result(
                        "INVALID_RESPONSE",
                        "VirusTotal returned invalid analysis statistics.",
                    )

                if (
                    malicious < 0
                    or suspicious < 0
                    or total <= 0
                    or malicious + suspicious > total
                ):
                    return self._error_result(
                        "INVALID_RESPONSE",
                        "VirusTotal returned inconsistent analysis statistics.",
                    )

                positives = malicious + suspicious

                permalink = (
                    f"https://www.virustotal.com/gui/file/{sha256_hash}"
                )

                logger.info(
                    "VirusTotal lookup completed: "
                    "%s/%s detections.",
                    positives,
                    total,
                )

                return {
                    "used_fallback": True,
                    "status": "SUCCESS",
                    "positives": positives,
                    "total_engines": total,
                    "permalink": permalink,
                    "scans": attributes.get(
                        "last_analysis_results",
                        {},
                    ),
                    "message": None,
                }

            # 5. Hash not found
            elif response.status_code == 404:

                logger.info(
                    "Hash not found in VirusTotal: %s",
                    sha256_hash,
                )

                return self._error_result(
                    "NOT_FOUND",
                    "File hash not found in VirusTotal database.",
                )

            # 6. Rate limit
            elif response.status_code == 429:

                logger.warning(
                    "VirusTotal API rate limit reached."
                )

                return self._error_result(
                    "RATE_LIMITED",
                    "VirusTotal API rate limit reached.",
                )

            # 7. Unauthorized
            elif response.status_code in [401, 403]:

                logger.error(
                    "VirusTotal API authentication or permission error: %s",
                    response.status_code,
                )

                return self._error_result(
                    f"HTTP_{response.status_code}",
                    "VirusTotal API authentication or permission failed.",
                )

            # 8. Other HTTP errors
            else:

                logger.error(
                    "VirusTotal returned HTTP %s.",
                    response.status_code,
                )

                return self._error_result(
                    f"HTTP_{response.status_code}",
                    f"VirusTotal returned HTTP {response.status_code}.",
                )

        except requests.Timeout:

            logger.warning(
                "VirusTotal API request timed out."
            )

            return self._error_result(
                "TIMEOUT",
                "VirusTotal request timed out.",
            )

        except requests.RequestException as e:

            logger.error(
                "VirusTotal network error: %s",
                e,
            )

            return self._error_result(
                "NETWORK_ERROR",
                "Unable to connect to VirusTotal.",
            )

        except Exception:

            logger.exception(
                "Unexpected VirusTotal lookup error."
            )

            return self._error_result(
                "ERROR",
                "An unexpected VirusTotal lookup error occurred.",
            )


virustotal_service = VirusTotalService()

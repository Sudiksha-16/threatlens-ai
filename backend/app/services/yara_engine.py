import os
import logging
import threading

from typing import List, Dict, Any

import yara

from backend.app.config.settings import settings


logger = logging.getLogger("threatlens.yara_engine")


# Maximum time allowed for a YARA scan, in seconds.
YARA_SCAN_TIMEOUT = 30


class YaraEngine:

    def __init__(self):
        self.rules = None
        self.rules_available = False
        self.rules_path = settings.YARA_RULES_PATH
        self._lock = threading.Lock()

        self._load_rules()

    def _load_rules(self):
        """Load and compile the configured YARA rules file."""

        if not self.rules_path:
            logger.warning(
                "YARA rules path is not configured."
            )
            return

        if not os.path.isfile(self.rules_path):
            logger.warning(
                "YARA rules file not found: %s",
                self.rules_path,
            )
            return

        try:
            compiled_rules = yara.compile(
                filepath=self.rules_path
            )

            with self._lock:
                self.rules = compiled_rules
                self.rules_available = True

            logger.info(
                "YARA rules loaded successfully from %s",
                self.rules_path,
            )

        except yara.Error as error:
            logger.exception(
                "Failed to compile YARA rules: %s",
                error,
            )

            self.rules = None
            self.rules_available = False

        except Exception:
            logger.exception(
                "Unexpected error while loading YARA rules."
            )

            self.rules = None
            self.rules_available = False

    def reload_rules(self) -> bool:
        """
        Reload YARA rules.

        Returns True when compilation succeeds, otherwise False.
        """

        self.rules = None
        self.rules_available = False

        self._load_rules()

        return self.rules_available

    def scan_file(
        self,
        file_path: str,
    ) -> List[Dict[str, Any]]:
        """
        Scan a file and return normalized YARA matches.

        Returns an empty list when:
        - Rules are unavailable.
        - The file does not exist.
        - The file cannot be scanned.
        - No rules match.

        Check rules_available separately to distinguish unavailable
        YARA from a successful scan with no matches.
        """

        if not self.rules_available or self.rules is None:
            logger.warning(
                "YARA scan skipped because rules are unavailable."
            )
            return []

        if not file_path or not os.path.isfile(file_path):
            logger.warning(
                "YARA scan skipped: invalid file path."
            )
            return []

        try:
            raw_matches = self.rules.match(
                filepath=file_path,
                timeout=YARA_SCAN_TIMEOUT,
            )

            matches = []

            for match in raw_matches:
                metadata = match.meta or {}

                severity = str(
                    metadata.get("severity", "Medium")
                ).capitalize()

                if severity not in {
                    "Low",
                    "Medium",
                    "High",
                    "Critical",
                }:
                    severity = "Medium"

                tags = list(match.tags or [])

                matches.append({
                    "rule_name": str(match.rule),

                    "category": str(
                        metadata.get(
                            "category",
                            "General",
                        )
                    ),

                    "severity": severity,

                    "tags": tags,

                    "description": str(
                        metadata.get(
                            "description",
                            "Matched YARA signature",
                        )
                    ),
                })

            logger.info(
                "YARA scan completed for %s. Matches: %s",
                os.path.basename(file_path),
                len(matches),
            )

            return matches

        except yara.TimeoutError:
            logger.error(
                "YARA scan timed out for %s",
                file_path,
            )
            return []

        except yara.Error:
            logger.exception(
                "YARA scanning error for %s",
                file_path,
            )
            return []

        except OSError:
            logger.exception(
                "File access error during YARA scan: %s",
                file_path,
            )
            return []

        except Exception:
            logger.exception(
                "Unexpected YARA scan error for %s",
                file_path,
            )
            return []


# Shared YARA engine instance.
yara_engine = YaraEngine()

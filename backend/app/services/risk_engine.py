import logging
from typing import Dict, Any, List

logger = logging.getLogger("threatlens.risk_engine")


class RiskAssessmentEngine:

    def calculate_risk(
        self,
        static_analysis: Dict[str, Any],
        yara_matches: List[Dict[str, Any]],
        ml_prediction: Dict[str, Any] = None,
        vt_result: Dict[str, Any] = None,
    ) -> Dict[str, Any]:

        score = 0
        reasons = []
        recommendations = []

        # -------------------------------------------------
        # 1. MACHINE LEARNING CONTRIBUTION (MAX 45 POINTS)
        # -------------------------------------------------

        if isinstance(ml_prediction, dict):

            probabilities = ml_prediction.get(
                "class_probabilities",
                {},
            )

            p_malicious = float(
                probabilities.get("Malicious", 0.0)
            )

            if not 0.0 <= p_malicious <= 1.0:
                raise ValueError(
                    "Invalid malicious probability supplied to risk engine."
                )

            model_name = ml_prediction.get(
                "model_name",
                "ML Model",
            ).replace("_", " ")

            is_malicious = ml_prediction.get(
                "is_malicious",
                False,
            )

            # Probability-based contribution.
            ml_points = round(p_malicious * 45)

            score += ml_points

            reasons.append(
                f"{model_name} estimated a "
                f"{p_malicious * 100:.1f}% malicious probability "
                f"(+{ml_points} risk points)."
            )

            if is_malicious:
                recommendations.append(
                    "Treat the file as suspicious and do not execute "
                    "it until its indicators have been investigated."
                )

            elif p_malicious >= 0.30:
                recommendations.append(
                    "The model predicted Benign but the malicious "
                    "probability is elevated. Further investigation "
                    "is recommended."
                )

        # -------------------------------------------------
        # 2. VIRUSTOTAL CONTRIBUTION (MAX 50 POINTS)
        # Used when local ML is unavailable.
        # -------------------------------------------------

        elif (
            isinstance(vt_result, dict)
            and vt_result.get("status") == "SUCCESS"
        ):

            positives = max(
                0,
                int(vt_result.get("positives", 0)),
            )

            total_engines = max(
                0,
                int(vt_result.get("total_engines", 0)),
            )

            if total_engines > 0:

                detection_ratio = min(
                    positives / total_engines,
                    1.0,
                )

                vt_points = round(
                    detection_ratio * 50
                )

                score += vt_points

                reasons.append(
                    f"VirusTotal reported {positives} detections "
                    f"out of {total_engines} engines "
                    f"(+{vt_points} risk points)."
                )

                if positives > 0:
                    recommendations.append(
                        "Investigate the VirusTotal detection results "
                        "and verify the reported indicators."
                    )

                else:
                    reasons.append(
                        "VirusTotal reported no malicious or "
                        "suspicious detections. This does not prove "
                        "the file is safe."
                    )

            else:
                reasons.append(
                    "VirusTotal returned no usable engine statistics."
                )

        elif vt_result:
            reasons.append(
                "VirusTotal did not provide a conclusive result. "
                "No VirusTotal risk points were assigned."
            )

        # -------------------------------------------------
        # 3. YARA SIGNATURE CONTRIBUTION (MAX 35 POINTS)
        # -------------------------------------------------

        if yara_matches:

            critical_matches = [
                match for match in yara_matches
                if match.get("severity") == "Critical"
            ]

            high_matches = [
                match for match in yara_matches
                if match.get("severity") == "High"
            ]

            medium_matches = [
                match for match in yara_matches
                if match.get("severity") == "Medium"
            ]

            yara_points = 0

            if critical_matches:
                yara_points += 25

                match = critical_matches[0]

                reasons.append(
                    f"Critical YARA signature detected: "
                    f"{match.get('rule_name', 'Unknown rule')}."
                )

            elif high_matches:
                yara_points += 18

                match = high_matches[0]

                reasons.append(
                    f"High-severity YARA signature detected: "
                    f"{match.get('rule_name', 'Unknown rule')}."
                )

            elif medium_matches:
                yara_points += 10

                match = medium_matches[0]

                reasons.append(
                    f"Medium-severity YARA signature detected: "
                    f"{match.get('rule_name', 'Unknown rule')}."
                )

            # Additional matches contribute points.
            if len(yara_matches) > 1:
                extra_points = min(
                    10,
                    (len(yara_matches) - 1) * 5,
                )

                yara_points += extra_points

                reasons.append(
                    f"{len(yara_matches)} YARA rules matched."
                )

            yara_points = min(yara_points, 35)

            score += yara_points

            recommendations.append(
                "Review the matched YARA signatures and their "
                "associated indicators."
            )

        # -------------------------------------------------
        # 4. STATIC ANALYSIS CONTRIBUTION (MAX 25 POINTS)
        # -------------------------------------------------

        static_points = 0

        entropy = float(
            static_analysis.get("entropy", 0.0) or 0.0
        )

        obfuscation = (
            static_analysis.get("obfuscation_indicators") or []
        )

        imported_apis = (
            static_analysis.get("imported_apis") or []
        )

        suspicious_strings = (
            static_analysis.get("suspicious_strings") or []
        )

        # Entropy
        if entropy > 7.4:

            static_points += 10

            reasons.append(
                f"High file entropy ({entropy:.2f}/8.0) "
                "may indicate compression, packing or encryption."
            )

        elif entropy > 7.0:

            static_points += 5

            reasons.append(
                f"Elevated file entropy ({entropy:.2f}/8.0) "
                "was observed."
            )

        # Obfuscation indicators
        if obfuscation:

            points = min(
                10,
                len(obfuscation) * 5,
            )

            static_points += points

            reasons.append(
                f"{len(obfuscation)} obfuscation or "
                f"structural indicators detected (+{points} points)."
            )

        # Security-sensitive APIs
        if imported_apis:

            points = min(
                10,
                len(imported_apis) * 2,
            )

            static_points += points

            reasons.append(
                f"{len(imported_apis)} security-sensitive API "
                "imports identified."
            )

        # Suspicious strings
        if suspicious_strings:

            points = min(
                8,
                len(suspicious_strings) * 2,
            )

            static_points += points

            reasons.append(
                f"{len(suspicious_strings)} suspicious strings "
                "identified."
            )

        # Enforce the maximum static contribution.
        static_points = min(
            static_points,
            25,
        )

        score += static_points

        # -------------------------------------------------
        # 5. FINAL RISK SCORE
        # -------------------------------------------------

        final_score = max(
            0,
            min(100, round(score)),
        )

        # -------------------------------------------------
        # 6. RISK LEVEL
        # -------------------------------------------------

        if final_score >= 81:

            level = "Critical"

            recommendations.extend([
                "Immediately isolate the file from normal use.",
                "Do not execute the file on production systems.",
                "Investigate related indicators of compromise.",
                "Follow your organization's incident response process.",
            ])

        elif final_score >= 56:

            level = "High"

            recommendations.extend([
                "Do not execute the file until it has been investigated.",
                "Review its indicators and detection evidence.",
                "Use an isolated analysis environment if further "
                "investigation is required.",
            ])

        elif final_score >= 26:

            level = "Medium"

            recommendations.extend([
                "Perform additional security analysis.",
                "Review the detected structural indicators and "
                "available threat intelligence.",
            ])

        else:

            level = "Low"

            if not ml_prediction and not (
                vt_result
                and vt_result.get("status") == "SUCCESS"
                and vt_result.get("total_engines", 0) > 0
            ) and not yara_matches:

                recommendations.append(
                    "Insufficient conclusive threat intelligence. "
                    "A low score does not establish that the file is safe."
                )

            else:

                recommendations.append(
                    "No strong malicious indicators were identified "
                    "by the available analysis methods. This is not "
                    "a guarantee that the file is safe."
                )

        # Remove duplicate recommendations.
        recommendations = list(
            dict.fromkeys(recommendations)
        )

        return {
            "risk_score": final_score,
            "risk_level": level,
            "reasons": reasons,
            "recommended_actions": recommendations,
        }


risk_engine = RiskAssessmentEngine()

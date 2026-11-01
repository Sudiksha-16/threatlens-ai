
import os
import math
import re
import hashlib
import logging
from collections import Counter
from typing import Dict, Any, List, Tuple

import pefile


logger = logging.getLogger("threatlens.file_analyzer")


SUSPICIOUS_APIS = {
    "Process Injection": [
        "VirtualAlloc",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "QueueUserAPC",
        "SetThreadContext",
        "ResumeThread",
    ],
    "Anti-Debugging": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
    ],
    "Credential Access": [
        "CryptUnprotectData",
        "LsaRetrievePrivateData",
        "CredEnumerateA",
        "SamIConnect",
    ],
    "Persistence": [
        "RegSetValueExA",
        "RegSetValueExW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
    ],
    "Evasion & Execution": [
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessA",
        "CreateProcessW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
    ],
}


SUSPICIOUS_SECTION_NAMES = [
    "upx0",
    "upx1",
    "upx2",
    "aspack",
    "fsg",
    "mew",
    "mpress",
    "petite",
    "pecompact",
    "themida",
    "vmp",
    "pec",
    ".pack",
    ".sforce",
]


URL_PATTERN = re.compile(
    rb"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}"
    rb"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\b"
)


SUSPICIOUS_KEYWORDS = [
    b"powershell",
    b"cmd.exe",
    b"vssadmin",
    b"delete shadows",
    b"wmic",
    b"bitcoin",
    b"wallet",
    b".onion",
    b"encrypted",
    b"ransom",
    b"mimikatz",
    b"inject",
    b"reg add",
    b"schtasks",
    b"net user",
    b"taskkill",
]


# Limits memory use when inspecting uploaded files.
READ_CHUNK_SIZE = 65536
MAX_STRING_SCAN_SIZE = 50 * 1024 * 1024


def calculate_hashes(file_path: str) -> Tuple[str, str]:
    """Calculate SHA-256 and MD5 hashes without loading the whole file."""

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(READ_CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)
            md5.update(chunk)

    return sha256.hexdigest(), md5.hexdigest()


def calculate_entropy(file_path: str) -> float:
    """Calculate Shannon entropy of a file using a byte-frequency counter."""

    occurrences = [0] * 256
    total_bytes = 0

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(READ_CHUNK_SIZE)

            if not chunk:
                break

            total_bytes += len(chunk)

            for byte in chunk:
                occurrences[byte] += 1

    if total_bytes == 0:
        return 0.0

    entropy = 0.0

    for count in occurrences:
        if count:
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def extract_strings(
    file_path: str,
    min_len: int = 4,
    max_strings: int = 200,
) -> Tuple[List[str], List[str], List[str]]:
    """
    Extract URLs, IP addresses and suspicious keywords.

    The scan is limited to the first 50 MB to avoid excessive memory use.
    """

    urls = set()
    ips = set()
    suspicious = set()

    try:
        with open(file_path, "rb") as file:
            content = file.read(MAX_STRING_SCAN_SIZE)

        # Extract URLs.
        for match in URL_PATTERN.findall(content):
            value = match.decode("ascii", errors="ignore")

            if len(value) >= min_len:
                urls.add(value)

            if len(urls) >= max_strings:
                break

        # Extract IP addresses.
        for match in IP_PATTERN.findall(content):
            ip_address = match.decode("ascii", errors="ignore")

            if not ip_address.startswith(("127.", "0.", "255.")):
                ips.add(ip_address)

            if len(ips) >= max_strings:
                break

        # Search for suspicious strings.
        content_lower = content.lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in content_lower:
                suspicious.add(
                    keyword.decode("ascii", errors="ignore")
                )

    except OSError as error:
        logger.warning(
            "Could not extract strings from %s: %s",
            file_path,
            error,
        )

    return (
        sorted(urls)[:max_strings],
        sorted(ips)[:max_strings],
        sorted(suspicious),
    )


def analyze_pe_file(
    file_path: str,
    is_deep: bool = False,
) -> Dict[str, Any]:
    """Extract PE headers, sections, imported APIs and obfuscation indicators."""

    pe_data = {
        "is_pe": False,
        "magic_info": "Unknown",
        "pe_headers": {},
        "sections": [],
        "imported_apis": [],
        "obfuscation_indicators": [],
    }

    pe = None

    try:
        # A valid PE file normally begins with the DOS MZ signature.
        with open(file_path, "rb") as file:
            header_bytes = file.read(2)

        if header_bytes != b"MZ":
            pe_data["magic_info"] = "Non-PE File"
            return pe_data

        # Parse the file. pefile validates the PE structure beyond the MZ signature.
        pe = pefile.PE(
            file_path,
            fast_load=not is_deep,
        )

        if not hasattr(pe, "FILE_HEADER") or not hasattr(pe, "OPTIONAL_HEADER"):
            pe_data["magic_info"] = "Invalid or Incomplete PE File"
            return pe_data

        pe_data["is_pe"] = True
        pe_data["magic_info"] = "Windows Portable Executable (PE32/PE32+)"

        # File headers.
        pe_data["pe_headers"] = {
            "NumberOfSections": pe.FILE_HEADER.NumberOfSections,
            "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
            "Characteristics": pe.FILE_HEADER.Characteristics,
            "SizeOfOptionalHeader": pe.FILE_HEADER.SizeOfOptionalHeader,
            "Machine": hex(pe.FILE_HEADER.Machine),
        }

        # Optional headers.
        opt = pe.OPTIONAL_HEADER

        pe_data["pe_headers"].update({
            "AddressOfEntryPoint": opt.AddressOfEntryPoint,
            "ImageBase": opt.ImageBase,
            "SectionAlignment": opt.SectionAlignment,
            "FileAlignment": opt.FileAlignment,
            "MajorOperatingSystemVersion": opt.MajorOperatingSystemVersion,
            "MinorOperatingSystemVersion": opt.MinorOperatingSystemVersion,
            "MajorImageVersion": opt.MajorImageVersion,
            "MinorImageVersion": opt.MinorImageVersion,
            "SizeOfImage": opt.SizeOfImage,
            "SizeOfHeaders": opt.SizeOfHeaders,
            "CheckSum": opt.CheckSum,
            "Subsystem": opt.Subsystem,
            "DllCharacteristics": opt.DllCharacteristics,
            "SizeOfStackReserve": opt.SizeOfStackReserve,
            "SizeOfHeapReserve": opt.SizeOfHeapReserve,
        })

        # Analyze PE sections.
        suspicious_sections_count = 0

        for section in pe.sections:
            try:
                section_name = (
                    section.Name.decode("utf-8", errors="ignore")
                    .strip("\x00")
                    .lower()
                )
            except Exception:
                section_name = "unknown"

            section_entropy = round(section.get_entropy(), 4)
            is_suspicious = False

            if any(
                suspicious_name in section_name
                for suspicious_name in SUSPICIOUS_SECTION_NAMES
            ):
                is_suspicious = True

                pe_data["obfuscation_indicators"].append(
                    f"Suspicious section name '{section_name}' detected"
                )

            if section_entropy > 7.2:
                is_suspicious = True

                pe_data["obfuscation_indicators"].append(
                    f"High entropy ({section_entropy}) in section "
                    f"'{section_name}'"
                )

            # Check whether a section is both writable and executable.
            is_writable = bool(section.Characteristics & 0x80000000)
            is_executable = bool(section.Characteristics & 0x20000000)

            if is_writable and is_executable:
                is_suspicious = True

                pe_data["obfuscation_indicators"].append(
                    f"Section '{section_name}' is both writable and executable"
                )

            if is_suspicious:
                suspicious_sections_count += 1

            pe_data["sections"].append({
                "name": section_name,
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": section_entropy,
                "characteristics": hex(section.Characteristics),
                "is_suspicious": is_suspicious,
            })

        pe_data["pe_headers"]["suspicious_sections_count"] = (
            suspicious_sections_count
        )

        pe_data["pe_headers"]["total_sections"] = len(pe.sections)

        # Parse imports if they were not loaded during fast parsing.
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            try:
                pe.parse_data_directories(
                    directories=[
                        pefile.DIRECTORY_ENTRY[
                            "IMAGE_DIRECTORY_ENTRY_IMPORT"
                        ]
                    ]
                )
            except Exception as error:
                logger.debug("Import directory parsing failed: %s", error)

        matched_apis = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imported_function in entry.imports:
                    if not imported_function or not imported_function.name:
                        continue

                    api_name = imported_function.name.decode(
                        "utf-8",
                        errors="ignore",
                    )

                    for category, api_list in SUSPICIOUS_APIS.items():
                        if any(
                            target.lower() == api_name.lower()
                            for target in api_list
                        ):
                            matched_apis.append(
                                f"{api_name} [{category}]"
                            )

        pe_data["imported_apis"] = sorted(set(matched_apis))[:50]

    except pefile.PEFormatError as error:
        logger.warning("Invalid PE file %s: %s", file_path, error)
        pe_data["magic_info"] = "Invalid PE File"

    except (OSError, ValueError, AttributeError, IndexError) as error:
        logger.warning("Error parsing PE file %s: %s", file_path, error)
        pe_data["magic_info"] = "PE Parsing Error"

    except Exception:
        logger.exception("Unexpected PE analysis error for %s", file_path)
        pe_data["magic_info"] = "PE Parsing Error"

    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass

    return pe_data


def detect_file_type(file_path: str, is_pe: bool) -> str:
    """Identify common file formats using their signatures."""

    if is_pe:
        return "Win32/Win64 Executable (PE)"

    with open(file_path, "rb") as file:
        header = file.read(16)

    if header.startswith(b"\x7fELF"):
        return "Linux Executable (ELF)"

    if header.startswith(b"%PDF"):
        return "PDF Document"

    if header.startswith(b"PK\x03\x04"):
        return "ZIP / Archive Container"

    if header.startswith(b"\x1f\x8b"):
        return "GZIP Archive"

    if header.startswith(b"Rar!\x1a\x07"):
        return "RAR Archive"

    if header.startswith(b"#!"):
        return "Script File"

    if header.startswith(b"\xd0\xcf\x11\xe0"):
        return "Microsoft Office / OLE Document"

    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG Image"

    if header.startswith(b"\xff\xd8\xff"):
        return "JPEG Image"

    if header.startswith((b"GIF87a", b"GIF89a")):
        return "GIF Image"

    if header.startswith(b"BM"):
        return "BMP Image"

    return "Unknown Binary"


def perform_static_analysis(
    file_path: str,
    scan_mode: str = "standard",
) -> Dict[str, Any]:
    """Perform safe static analysis without executing the uploaded file."""

    if not os.path.isfile(file_path):
        raise FileNotFoundError("Uploaded file does not exist.")

    is_deep = str(scan_mode).lower() == "deep"

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)

    sha256, md5 = calculate_hashes(file_path)

    entropy = calculate_entropy(file_path)

    pe_data = analyze_pe_file(
        file_path,
        is_deep=is_deep,
    )

    urls, ips, suspicious_strings = extract_strings(
        file_path,
        min_len=4,
        max_strings=300 if is_deep else 100,
    )

    file_type = detect_file_type(
        file_path,
        pe_data["is_pe"],
    )

    # High entropy can indicate compression, packing or encryption.
    # It is an indicator only, not proof of malware.
    if entropy > 7.3:
        pe_data["obfuscation_indicators"].append(
            f"High overall file entropy: {entropy}/8.0"
        )

    return {
        "file_name": file_name,
        "file_size": file_size,
        "file_type": file_type,
        "sha256": sha256,
        "md5": md5,
        "entropy": entropy,
        "is_pe": pe_data["is_pe"],
        "magic_info": pe_data["magic_info"],
        "pe_headers": pe_data["pe_headers"],
        "sections": pe_data["sections"],
        "imported_apis": pe_data["imported_apis"],
        "embedded_urls": urls,
        "embedded_ips": ips,
        "suspicious_strings": suspicious_strings,
        "obfuscation_indicators": list(
            dict.fromkeys(pe_data["obfuscation_indicators"])
        ),
    }

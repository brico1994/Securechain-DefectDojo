from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def risk_to_severity(risk: float) -> str:
    if risk >= 9.0:
        return "Critical"
    if risk >= 7.0:
        return "High"
    if risk >= 4.0:
        return "Medium"
    if risk >= 1.0:
        return "Low"
    return "Info"


def normalize_purl(purl: Optional[str]) -> Optional[str]:
    if not purl:
        return None
    return purl.strip()


def parse_sbom_components(sbom: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """
    Returns map: purl -> {name, version, bom_ref}
    CycloneDX: components[].purl OR fallback properties spdx external reference.
    """
    out: Dict[str, Dict[str, str]] = {}
    for c in sbom.get("components", []) or []:
        purl = c.get("purl")

        if not purl:
            for prop in (c.get("properties", []) or []):
                if prop.get("name") == "spdx:external-reference:package-manager:purl":
                    purl = prop.get("value")
                    break

        purl = normalize_purl(purl)
        if not purl:
            continue

        out[purl] = {
            "name": c.get("name", "") or "",
            "version": c.get("version", "") or "",
            "bom_ref": (c.get("bom-ref", "") or c.get("bom_ref", "") or ""),
        }
    return out


def extract_first_cwe_id(tix_vuln: Dict[str, Any]) -> int:
    cwes = (tix_vuln or {}).get("cwes") or []
    for c in cwes:
        cid = c.get("name") or ""
        if isinstance(cid, str) and cid.startswith("CWE-"):
            try:
                return int(cid.split("-", 1)[1])
            except Exception:
                pass

        url = c.get("@id") or ""
        if isinstance(url, str) and "definitions/" in url:
            try:
                tail = url.split("definitions/", 1)[1]
                num = tail.split(".", 1)[0].split("/", 1)[0]
                return int(num)
            except Exception:
                pass
    return 0


def score_risk(
    cvss: Optional[float],
    reachable: List[Any],
    exploits: List[Any],
    vex_status: Optional[str],
    vex_priority: Optional[float] = None,
) -> float:
    base = float(cvss or 0.0)

    if (vex_status or "").lower() == "not_affected":
        return 0.0

    if reachable and len(reachable) > 0:
        base *= 1.2
    if exploits and len(exploits) > 0:
        base *= 1.3

    if vex_priority is not None:
        try:
            vp = float(vex_priority)
            base = (0.85 * base) + (0.15 * vp)
        except Exception:
            pass

    return clamp(base, 0.0, 10.0)


def vex_flags(vex_status: Optional[str]) -> Dict[str, bool]:
    s = (vex_status or "").lower().strip()
    flags = {
        "active": True,
        "verified": True,
        "false_p": False,
        "is_mitigated": False,
        "under_review": False,
    }

    if s == "affected":
        return flags

    if s == "not_affected":
        return {
            "active": False,
            "verified": True,
            "false_p": True,
            "is_mitigated": False,
            "under_review": False,
        }

    if s == "fixed":
        return {
            "active": False,
            "verified": True,
            "false_p": False,
            "is_mitigated": True,
            "under_review": False,
        }

    if s == "under_investigation":
        return {
            "active": True,
            "verified": False,
            "false_p": False,
            "is_mitigated": False,
            "under_review": True,
        }

    return flags


def build_indexes(
    vex: Dict[str, Any],
    tix: Dict[str, Any],
) -> Tuple[Dict[Tuple[str, str], Dict[str, Any]], Dict[Tuple[str, str], Dict[str, Any]]]:
    """
    Create indexes by (purl, vuln_name) -> statement
    """
    vex_idx: Dict[Tuple[str, str], Dict[str, Any]] = {}
    tix_idx: Dict[Tuple[str, str], Dict[str, Any]] = {}

    vex_statements = (((vex.get("metadata") or {}).get("statements")) or [])
    for st in vex_statements:
        vuln = st.get("vulnerability") or {}
        vuln_name = vuln.get("name") or vuln.get("@id") or ""
        products = st.get("products") or []
        for p in products:
            purl = normalize_purl(((p.get("identifiers") or {}).get("purl")))
            if not purl or not vuln_name:
                continue
            vex_idx[(purl, vuln_name)] = st

    tix_statements = (((tix.get("metadata") or {}).get("statements")) or [])
    for st in tix_statements:
        vuln = st.get("vulnerability") or {}
        vuln_name = vuln.get("name") or vuln.get("@id") or ""
        products = st.get("products") or []
        for p in products:
            purl = normalize_purl(((p.get("identifiers") or {}).get("purl")))
            if not purl or not vuln_name:
                continue
            tix_idx[(purl, vuln_name)] = st

    return vex_idx, tix_idx


def best_vuln_id(vuln: Dict[str, Any]) -> str:
    return vuln.get("name") or vuln.get("@id") or "UNKNOWN-VULN"


def _default_owner_repo(owner: Optional[str], repo: Optional[str]) -> Tuple[str, str]:
    return (owner or "unknown-owner", repo or "unknown-repo")


def _default_sbom_name(sbom_name: Optional[str]) -> str:
    return sbom_name or "sbom"


def build_finding(
    owner: str,
    repo: str,
    sbom_name: str,
    purl: str,
    component: Dict[str, str],
    vuln_name: str,
    vex_stmt: Optional[Dict[str, Any]],
    tix_stmt: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    tix_vuln = (tix_stmt or {}).get("vulnerability") or {}
    vex_vuln = (vex_stmt or {}).get("vulnerability") or {}
    vuln = tix_vuln if tix_vuln else vex_vuln

    vuln_id = best_vuln_id(vuln)
    vuln_desc = vuln.get("description") or ""

    # CVSS
    cvss_obj = (tix_vuln.get("cvss") or {}) if tix_vuln else {}
    cvss_score = cvss_obj.get("vuln_impact", None)
    cvss_vector = cvss_obj.get("attack_vector", "")

    # TIX evidence
    reachable = (tix_stmt or {}).get("reachable_code") or []
    exploits = (tix_stmt or {}).get("exploits") or []
    cwe = extract_first_cwe_id(tix_vuln)

    # VEX fields
    vex_status = (vex_stmt or {}).get("status")
    vex_just = (vex_stmt or {}).get("justification")
    vex_impact_stmt = (vex_stmt or {}).get("impact_statement")
    vex_priority = (vex_stmt or {}).get("priority", None)

    risk = score_risk(cvss_score, reachable, exploits, vex_status, vex_priority)
    severity = risk_to_severity(risk)
    flags = vex_flags(vex_status)

    title = f"[{vuln_id}] {component.get('name','')}@{component.get('version','')} ({purl})"

    references: List[str] = []
    if isinstance(vuln.get("@id"), str) and vuln.get("@id"):
        references.append(vuln["@id"])
    if isinstance(vuln_id, str):
        if vuln_id.startswith("CVE-"):
            references.append(f"https://nvd.nist.gov/vuln/detail/{vuln_id}")
        if vuln_id.startswith("GHSA-"):
            references.append(f"https://github.com/advisories/{vuln_id}")
    references.append(f"repo:{owner}/{repo}")
    references.append(f"purl:{purl}")

    description_lines: List[str] = [
        f"Repository: {owner}/{repo}",
        f"Component: {component.get('name','')} {component.get('version','')}",
        f"PURL: {purl}",
        f"SBOM: {sbom_name}",
        "",
        f"Vulnerability: {vuln_id}",
    ]
    if vuln_desc:
        description_lines.append(f"Description: {vuln_desc}")

    description_lines += [
        "",
        "VEX:",
        f"- status: {vex_status or 'unknown'}",
        f"- justification: {vex_just or 'n/a'}",
        f"- impact_statement: {vex_impact_stmt or 'n/a'}",
        f"- priority: {vex_priority if vex_priority is not None else 'n/a'}",
        "",
        "TIX:",
        f"- cvss_score: {cvss_score if cvss_score is not None else 'n/a'}",
        f"- cvss_vector: {cvss_vector or 'n/a'}",
        f"- reachable_code_count: {len(reachable)}",
        f"- exploits_count: {len(exploits)}",
        "",
        f"Computed risk: {risk:.2f} (severity={severity})",
    ]

    # Dojo fields (IMPORTANT: do NOT emit "duplicate")
    component_name = component.get("name", "") or ""
    component_version = component.get("version", "") or ""
    bom_ref = component.get("bom_ref", "") or ""

    # file_path: not truly a file path; we keep stable breadcrumb for Dojo UI.
    file_path = bom_ref or purl

    # Mitigation / Impact: keep simple and deterministic; can be improved later.
    if (vex_status or "").lower() == "fixed":
        mitigation = "Upgrade component to a fixed version (VEX status: fixed)."
    elif (vex_status or "").lower() == "not_affected":
        mitigation = "No action required (VEX status: not_affected)."
    else:
        mitigation = "Review and remediate according to project policy (patch/upgrade/configuration)."

    impact = vex_impact_stmt or vuln_desc or f"Computed risk score: {risk:.2f}"

    unique_id_from_tool = f"{owner}/{repo}|{sbom_name}|{purl}|{vuln_id}"

    tags = [
        "securechain",
        "generic_findings",
        f"owner:{owner}",
        f"repo:{repo}",
        f"sbom:{sbom_name}",
        f"purl:{purl}",
        f"vuln:{vuln_id}",
    ]

    finding: Dict[str, Any] = {
        "title": title,
        "severity": severity,
        "description": "\n".join(description_lines),
        "mitigation": mitigation,
        "impact": impact,
        "references": references,
        "cwe": cwe,
        "component_name": component_name,
        "component_version": component_version,
        "file_path": file_path,
        "unique_id_from_tool": unique_id_from_tool,
        "tags": tags,
        **flags,
        # NOTE: do NOT add "duplicate" (forbidden in your Dojo instance)
    }
    return finding


def generate_findings(
    sbom: Dict[str, Any],
    vex: Dict[str, Any],
    tix: Dict[str, Any],
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    sbom_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Core engine: SBOM+VEX+TIX dicts -> Dojo Generic Findings Import JSON envelope:
    { "findings": [ ... ] }
    """
    owner_s, repo_s = _default_owner_repo(owner, repo)
    sbom_name_s = _default_sbom_name(sbom_name)

    components = parse_sbom_components(sbom)
    vex_idx, tix_idx = build_indexes(vex, tix)

    # Union of keys from VEX/TIX. We only emit findings for purls present in SBOM.
    keys = set(vex_idx.keys()) | set(tix_idx.keys())

    findings: List[Dict[str, Any]] = []
    for (purl, vuln_name) in sorted(keys, key=lambda k: (k[0], k[1])):
        comp = components.get(purl)
        if not comp:
            # Contract from SecureChain knowledge: no vuln exists outside SBOM purl
            continue

        vex_stmt = vex_idx.get((purl, vuln_name))
        tix_stmt = tix_idx.get((purl, vuln_name))

        finding = build_finding(
            owner=owner_s,
            repo=repo_s,
            sbom_name=sbom_name_s,
            purl=purl,
            component=comp,
            vuln_name=vuln_name,
            vex_stmt=vex_stmt,
            tix_stmt=tix_stmt,
        )
        findings.append(finding)

    return {"findings": findings}


def generate_findings_from_paths(
    sbom_path: str,
    vex_path: str,
    tix_path: str,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
    sbom_name: Optional[str] = None,
) -> Dict[str, Any]:
    sbom = load_json(sbom_path)
    vex = load_json(vex_path)
    tix = load_json(tix_path)
    return generate_findings(sbom, vex, tix, owner=owner, repo=repo, sbom_name=sbom_name)

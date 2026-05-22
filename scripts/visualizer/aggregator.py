from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RAIZ = Path(__file__).resolve().parents[2]
RUTA_REPOS = RAIZ / "data" / "repos"
RUTA_RESULTADOS = RAIZ / "data" / "results"
RUTA_REPOS_JSON = RAIZ / "data" / "repos.json"

SUFIJO_SBOM     = "-sbom.json"

# ── Detección de archivos CI/CD ────────────────────────────────────────────
_CICD_RE = [
    re.compile(r'\.github/workflows/.+\.(yml|yaml)$',    re.IGNORECASE),
    re.compile(r'(^|/)\.gitlab-ci\.(yml|yaml)$',         re.IGNORECASE),
    re.compile(r'(^|/)Jenkinsfile(\.\w+)?$'),
    re.compile(r'\.circleci/config\.(yml|yaml)$',        re.IGNORECASE),
    re.compile(r'(^|/)azure-pipelines(-\w+)?\.(yml|yaml)$', re.IGNORECASE),
    re.compile(r'(^|/)bitbucket-pipelines\.(yml|yaml)$', re.IGNORECASE),
    re.compile(r'(^|/)\.travis\.(yml|yaml)$',            re.IGNORECASE),
    re.compile(r'(^|/)appveyor\.(yml|yaml)$',            re.IGNORECASE),
    re.compile(r'(^|/)\.drone\.(yml|yaml)$',             re.IGNORECASE),
    re.compile(r'(^|/)cloudbuild\.(yaml|yml)$',          re.IGNORECASE),
    re.compile(r'\.buildkite/.+\.(yml|yaml)$',           re.IGNORECASE),
    re.compile(r'(^|/)wercker\.(yml|yaml)$',             re.IGNORECASE),
    re.compile(r'(^|/)codeship-\w+\.(yml|yaml)$',        re.IGNORECASE),
    re.compile(r'(^|/)circle\.(yml|yaml)$',              re.IGNORECASE),
]

_CICD_ARCHIVOS_RAIZ = [
    '.gitlab-ci.yml', '.gitlab-ci.yaml',
    'Jenkinsfile',
    'azure-pipelines.yml', 'azure-pipelines.yaml',
    'bitbucket-pipelines.yml', 'bitbucket-pipelines.yaml',
    '.travis.yml', '.travis.yaml',
    'appveyor.yml', 'appveyor.yaml',
    '.drone.yml', '.drone.yaml',
    'cloudbuild.yaml', 'cloudbuild.yml',
    'wercker.yml', 'circle.yml',
]
_CICD_SUBDIRS = ['.github/workflows', '.circleci', '.buildkite']


def _es_archivo_cicd(path: str | None) -> bool:
    if not path:
        return False
    p = path.replace('\\', '/')
    return any(pat.search(p) for pat in _CICD_RE)


def _plataforma_cicd(path: str) -> str:
    p = path.replace('\\', '/')
    if '.github/workflows'     in p: return 'GitHub Actions'
    if '.gitlab-ci'            in p: return 'GitLab CI'
    if 'Jenkinsfile'           in p: return 'Jenkins'
    if '.circleci'             in p: return 'CircleCI'
    if 'azure-pipelines'       in p.lower(): return 'Azure DevOps'
    if 'bitbucket-pipelines'   in p.lower(): return 'Bitbucket'
    if '.travis'               in p: return 'Travis CI'
    if 'appveyor'              in p.lower(): return 'AppVeyor'
    if '.drone'                in p: return 'Drone CI'
    if 'cloudbuild'            in p.lower(): return 'Cloud Build'
    if '.buildkite'            in p: return 'Buildkite'
    if 'wercker'               in p.lower(): return 'Wercker'
    return 'CI/CD'


def _contar_archivos_cicd() -> dict[str, list[dict]]:
    """Escanea los repos clonados y retorna {repo_id: [{file_path, platform}]}."""
    result: dict[str, list[dict]] = {}
    if not RUTA_REPOS.exists():
        return result
    for repo_dir in RUTA_REPOS.iterdir():
        if not repo_dir.is_dir():
            continue
        archivos: list[dict] = []
        # Archivos conocidos en la raíz
        for nombre in _CICD_ARCHIVOS_RAIZ:
            if (repo_dir / nombre).exists():
                archivos.append({'file_path': nombre, 'platform': _plataforma_cicd(nombre)})
        # Directorios específicos de CI/CD
        for subdir in _CICD_SUBDIRS:
            d = repo_dir / subdir
            if d.is_dir():
                for ext in ('*.yml', '*.yaml'):
                    for f in d.rglob(ext):
                        rel = str(f.relative_to(repo_dir)).replace('\\', '/')
                        archivos.append({'file_path': rel, 'platform': _plataforma_cicd(rel)})
        # Jenkinsfile con extensión
        for f in repo_dir.glob('Jenkinsfile.*'):
            archivos.append({'file_path': f.name, 'platform': 'Jenkins'})
        result[repo_dir.name] = archivos
    return result
SUFIJO_GRYPE = "-grype.json"
SUFIJO_GRYPE_RAW = "-grype-raw.json"
SUFIJO_GITLEAKS = "-gitleaks.json"
SUFIJO_CODEQL = "-codeql.json"


def _cargar_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _extraer_licencia(licenses: Any) -> str | None:
    if not licenses:
        return None
    if isinstance(licenses, list):
        for lic in licenses:
            if isinstance(lic, dict):
                valor = lic.get("value") or lic.get("spdxExpression") or lic.get("name")
                if valor:
                    return str(valor)
            elif isinstance(lic, str) and lic.strip():
                return lic
        return None
    if isinstance(licenses, str):
        return licenses
    return None


def _normalizar_severidad_grype(sev: Any) -> str:
    if not sev:
        return "unknown"
    s = str(sev).lower()
    if s in ("critical", "high", "medium", "low", "negligible", "unknown"):
        return s
    return "unknown"


def _mapear_severidad_codeql(level: Any, properties: Any) -> str:
    if isinstance(properties, dict):
        sev = properties.get("security-severity") or properties.get("securitySeverity")
        if sev is not None:
            try:
                score = float(sev)
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                return "low"
            except (TypeError, ValueError):
                pass
    nivel = (str(level) if level is not None else "").lower()
    if nivel == "error":
        return "high"
    if nivel == "warning":
        return "medium"
    if nivel == "note":
        return "low"
    return "unknown"


def _extraer_cwes(properties: Any) -> list[str]:
    cwes: list[str] = []
    if not isinstance(properties, dict):
        return cwes
    tags = properties.get("tags") or []
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and "cwe" in tag.lower():
                cwes.append(tag)
    return cwes


def _construir_repositorios() -> list[dict]:
    repos_dict: dict[str, dict] = {}

    data = _cargar_json(RUTA_REPOS_JSON) or {}
    for r in data.get("repositories", []):
        if not isinstance(r, dict):
            continue
        nombre = r.get("name") or Path(str(r.get("path", ""))).name
        if not nombre:
            continue
        repos_dict[nombre] = {
            "id": nombre,
            "name": nombre,
            "full_name": r.get("full_name") or nombre,
            "language": r.get("language"),
            "stars": r.get("stars", 0) or 0,
            "description": r.get("description"),
            "miner_status": "pending",
        }

    if RUTA_REPOS.exists():
        for d in RUTA_REPOS.iterdir():
            if not d.is_dir():
                continue
            entrada = repos_dict.get(d.name)
            esta_clonado = any(d.iterdir())
            estado = "cloned" if esta_clonado else "pending"
            if entrada is None:
                repos_dict[d.name] = {
                    "id": d.name,
                    "name": d.name,
                    "full_name": d.name,
                    "language": None,
                    "stars": 0,
                    "description": None,
                    "miner_status": estado,
                }
            else:
                entrada["miner_status"] = estado

    for sufijo in (SUFIJO_SBOM, SUFIJO_GRYPE, SUFIJO_GITLEAKS, SUFIJO_CODEQL):
        for path in RUTA_RESULTADOS.glob(f"*{sufijo}"):
            if sufijo == SUFIJO_GRYPE and path.name.endswith(SUFIJO_GRYPE_RAW):
                continue
            nombre = path.name[: -len(sufijo)]
            if nombre not in repos_dict:
                repos_dict[nombre] = {
                    "id": nombre,
                    "name": nombre,
                    "full_name": nombre,
                    "language": None,
                    "stars": 0,
                    "description": None,
                    "miner_status": "pending",
                }

    return sorted(repos_dict.values(), key=lambda x: x["name"])


def _procesar_sboms() -> tuple[list[dict], list[dict]]:
    componentes: list[dict] = []
    scans: list[dict] = []
    if not RUTA_RESULTADOS.exists():
        return componentes, scans
    for path in sorted(RUTA_RESULTADOS.glob(f"*{SUFIJO_SBOM}")):
        repo_id = path.name[: -len(SUFIJO_SBOM)]
        scans.append({"repo_id": repo_id})
        data = _cargar_json(path) or {}
        for art in data.get("artifacts", []) or []:
            if not isinstance(art, dict):
                continue
            componentes.append({
                "repo_id": repo_id,
                "name": art.get("name"),
                "version": art.get("version"),
                "ecosystem": art.get("type") or art.get("language"),
                "license": _extraer_licencia(art.get("licenses")),
                "purl": art.get("purl"),
            })
    return componentes, scans


def _procesar_grype() -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    scans: list[dict] = []
    if not RUTA_RESULTADOS.exists():
        return findings, scans
    for path in sorted(RUTA_RESULTADOS.glob(f"*{SUFIJO_GRYPE}")):
        if path.name.endswith(SUFIJO_GRYPE_RAW):
            continue
        repo_id = path.name[: -len(SUFIJO_GRYPE)]
        scans.append({"repo_id": repo_id})
        data = _cargar_json(path) or {}
        for v in data.get("vulnerabilities", []) or []:
            if not isinstance(v, dict):
                continue
            fix_raw = v.get("fix_version")
            fix_list: list[str] = []
            if fix_raw and str(fix_raw).strip().lower() not in ("n/a", "none", ""):
                if isinstance(fix_raw, list):
                    fix_list = [str(x) for x in fix_raw if x]
                else:
                    fix_list = [str(fix_raw)]
            cvss = v.get("cvss_score")
            try:
                cvss_val = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                cvss_val = None
            findings.append({
                "repo_id": repo_id,
                "vulnerability_id": v.get("vuln_id") or v.get("id"),
                "package_name": v.get("package_name"),
                "package_version": v.get("current_version") or v.get("version"),
                "package_type": v.get("type"),
                "severity": _normalizar_severidad_grype(v.get("vuln_severity") or v.get("severity")),
                "cvss_score": cvss_val,
                "fix_versions": fix_list,
                "description": v.get("message") or v.get("description"),
                "cwe": v.get("cwe"),
            })
    return findings, scans


def _procesar_gitleaks() -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    scans: list[dict] = []
    if not RUTA_RESULTADOS.exists():
        return findings, scans
    for path in sorted(RUTA_RESULTADOS.glob(f"*{SUFIJO_GITLEAKS}")):
        repo_id = path.name[: -len(SUFIJO_GITLEAKS)]
        scans.append({"repo_id": repo_id})
        data = _cargar_json(path) or {}
        for h in data.get("hallazgos", []) or []:
            if not isinstance(h, dict):
                continue
            inicio = h.get("StartLine") or h.get("startLine") or h.get("line")
            fin = h.get("EndLine") or h.get("endLine")
            fp = h.get("File") or h.get("file") or h.get("file_path")
            findings.append({
                "repo_id": repo_id,
                "rule_id": h.get("RuleID") or h.get("ruleID") or h.get("rule_id"),
                "description": h.get("Description") or h.get("description"),
                "file_path": fp,
                "is_cicd": _es_archivo_cicd(fp),
                "line": inicio,
                "line_start": inicio,
                "line_end": fin,
                "author": h.get("Author") or h.get("author"),
                "author_email": h.get("Email") or h.get("email"),
                "date": h.get("Date") or h.get("date"),
                "commit": h.get("Commit") or h.get("commit"),
                "match": h.get("Match"),
                "secret": h.get("Secret"),
                "tags": h.get("Tags"),
            })
    return findings, scans


def _procesar_codeql() -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    scans: list[dict] = []
    if not RUTA_RESULTADOS.exists():
        return findings, scans
    for path in sorted(RUTA_RESULTADOS.glob(f"*{SUFIJO_CODEQL}")):
        repo_id = path.name[: -len(SUFIJO_CODEQL)]
        scans.append({"repo_id": repo_id})
        data = _cargar_json(path) or {}
        for issue in data.get("issues", []) or []:
            if not isinstance(issue, dict):
                continue
            region = issue.get("region") or {}
            props = issue.get("properties") or {}
            mensaje = issue.get("message")
            if isinstance(mensaje, dict):
                mensaje = mensaje.get("text", "")
            inicio = region.get("startLine") if isinstance(region, dict) else None
            fin = region.get("endLine") if isinstance(region, dict) else None
            fp_cq = issue.get("file")
            findings.append({
                "repo_id": repo_id,
                "rule_id": issue.get("rule_id"),
                "severity": _mapear_severidad_codeql(issue.get("level"), props),
                "level": issue.get("level"),
                "message": mensaje,
                "file_path": fp_cq,
                "is_cicd": _es_archivo_cicd(fp_cq),
                "start_line": inicio,
                "end_line": fin,
                "cwe": _extraer_cwes(props),
            })
    return findings, scans


def construir_dataset() -> dict:
    sbom_components, sbom_scans = _procesar_sboms()
    grype_findings, grype_scans = _procesar_grype()
    gitleaks_findings, gitleaks_scans = _procesar_gitleaks()
    codeql_findings, codeql_scans = _procesar_codeql()

    cicd_por_repo = _contar_archivos_cicd()
    cicd_files = [
        {"repo_id": repo_id, "file_path": entry["file_path"], "platform": entry["platform"]}
        for repo_id, entries in cicd_por_repo.items()
        for entry in entries
    ]

    return {
        "meta": {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "scripts/visualizer/aggregator.py",
        },
        "repositories": _construir_repositorios(),
        "sbom_components": sbom_components,
        "sbom_scans": sbom_scans,
        "grype_findings": grype_findings,
        "grype_scans": grype_scans,
        "gitleaks_findings": gitleaks_findings,
        "gitleaks_scans": gitleaks_scans,
        "codeql_findings": codeql_findings,
        "codeql_scans": codeql_scans,
        "cicd_files": cicd_files,
    }


def calcular_mtime_fuentes() -> float:
    mtime_max = 0.0
    if RUTA_REPOS_JSON.exists():
        try:
            mtime_max = max(mtime_max, RUTA_REPOS_JSON.stat().st_mtime)
        except OSError:
            pass
    if RUTA_RESULTADOS.exists():
        for p in RUTA_RESULTADOS.glob("*.json"):
            try:
                mtime_max = max(mtime_max, p.stat().st_mtime)
            except OSError:
                pass
    if RUTA_REPOS.exists():
        try:
            mtime_max = max(mtime_max, RUTA_REPOS.stat().st_mtime)
        except OSError:
            pass
    return mtime_max


def main() -> int:
    dataset = construir_dataset()
    json.dump(dataset, sys.stdout, ensure_ascii=False, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

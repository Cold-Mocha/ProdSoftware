from __future__ import annotations

import json
import logging
import math
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
SCRIPTS = RAIZ / "scripts"
RUTA_VISUALIZER = SCRIPTS / "visualizer" / "serve.py"
sys.path.insert(0, str(SCRIPTS))

from add_submodules import _validate_repo_entry, _run_git_command
from generate_sboms import SBOMGenerator
from generate_grype import GrypeAnalyzer
from generate_gitleaks import EscanerGitleaks
from generate_codeql import CodeQLAnalyzer

RUTA_REPOS = RAIZ / "data" / "repos"
RUTA_RESULTADOS = RAIZ / "data" / "results"
RUTA_REPOS_JSON = RAIZ / "data" / "repos.json"

# Usa todos los núcleos disponibles para etapas livianas (clone/sbom/gitleaks/grype).
# CodeQL es CPU+RAM intensivo: se limita a la mitad de núcleos para no saturar la memoria.
_NCPUS         = os.cpu_count() or 4
WORKERS        = _NCPUS                          # workers totales
_WORKERS_CODEQL = max(1, _NCPUS // 2)           # máx. CodeQL en paralelo
_SEM_CODEQL    = threading.Semaphore(_WORKERS_CODEQL)

_R = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_BLUE = "\033[94m"
_MAGENTA = "\033[95m"
_CYAN = "\033[96m"
_WHITE = "\033[97m"

_STAGE_COLORS = {
    "clone":    _CYAN,
    "sbom":     _BLUE,
    "gitleaks": _MAGENTA,
    "grype":    _YELLOW,
    "codeql":   "\033[35m",  # magenta oscuro
}

_RE_OK    = re.compile(r"\b(ok)\b")
_RE_ERROR = re.compile(r"\b(ERROR)\b")
_RE_DASH  = re.compile(r"(?<!\w)(-{1})(?!\w|-)")


class ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)

        if not sys.stderr.isatty():
            return msg

        if record.levelno >= logging.ERROR:
            return f"{_RED}{msg}{_R}"

        if record.levelno >= logging.WARNING:
            return f"{_YELLOW}{msg}{_R}"

        raw = record.getMessage()

        # Separadores y cabeceras
        if set(raw.strip()) <= {"=", "-"} or "RESUMEN" in raw or "===" in raw:
            return f"{_BOLD}{_WHITE}{msg}{_R}"

        # Finalizado / Iniciando pipeline
        if "Pipeline finalizado" in raw or "Iniciando pipeline" in raw:
            return f"{_BOLD}{_GREEN}{msg}{_R}"

        # Dashboard
        if "Dashboard" in raw or "http://" in raw:
            return f"{_BOLD}{_CYAN}{msg}{_R}"

        # Filas del resumen (contienen "ok" o "ERROR" alineados)
        if _RE_OK.search(raw) or _RE_ERROR.search(raw):
            colored = _RE_OK.sub(f"{_GREEN}\\1{_R}", msg)
            colored = _RE_ERROR.sub(f"{_RED}\\1{_R}", colored)
            colored = _RE_DASH.sub(f"{_DIM}\\1{_R}", colored)
            return colored

        # Etapas por nombre
        raw_lower = raw.lower()
        for stage, color in _STAGE_COLORS.items():
            if stage in raw_lower:
                return f"{color}{msg}{_R}"

        return msg


if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

_handler = logging.getLogger().handlers[0] if logging.getLogger().handlers else None
if _handler:
    _handler.setFormatter(ColorFormatter("%(levelname)s | %(message)s"))

LOGGER = logging.getLogger(__name__)


def _ejecutar_subprocess(script: str) -> bool:
    resultado = subprocess.run(
        [sys.executable, str(SCRIPTS / script)],
        cwd=str(RAIZ),
        check=False,
    )
    return resultado.returncode == 0


def _lanzar_dashboard() -> subprocess.Popen | None:
    if not RUTA_VISUALIZER.exists():
        LOGGER.warning("Visualizer no encontrado en %s, se omite el dashboard", RUTA_VISUALIZER)
        return None

    proc = subprocess.Popen(
        [sys.executable, str(RUTA_VISUALIZER)],
        cwd=str(RAIZ),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    if proc.poll() is not None:
        LOGGER.warning("El dashboard termino inmediatamente (codigo=%s)", proc.returncode)
        return None

    puerto = os.environ.get("PORT", "4173")
    LOGGER.info("=" * 60)
    LOGGER.info("Dashboard activo en http://localhost:%s", puerto)
    LOGGER.info("Refresco automatico cada 500 ms mientras corre el pipeline")
    LOGGER.info("=" * 60)
    return proc


def _detener_dashboard(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _clonar_repo(repo_entry: dict) -> bool:
    try:
        url, path, ref = _validate_repo_entry(repo_entry)
    except ValueError as e:
        LOGGER.error("Clone | entrada invalida: %s", e)
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    path_exists = path.exists()
    path_is_empty = path_exists and path.is_dir() and not any(path.iterdir())

    if not path_exists or path_is_empty:
        LOGGER.info("Clone | Clonando %s...", path.name)
        if not _run_git_command(["git", "clone", url, str(path)], RAIZ, f"Fallo al clonar {url}"):
            return False
    elif not (path / ".git").exists():
        LOGGER.warning("Clone | %s existe pero no es un repo Git, se omite", path.name)
        return False
    else:
        LOGGER.info("Clone | %s ya existe, actualizando...", path.name)
        _run_git_command(["git", "fetch", "--all", "--prune"], path, f"Fallo al fetch {path.name}")

    if ref:
        _run_git_command(["git", "checkout", ref], path, f"Fallo al checkout {ref} en {path.name}")

    return True


def _procesar_repo(
    repo_entry: dict,
    sbom_gen: SBOMGenerator,
    grype_analyzer: GrypeAnalyzer,
    gitleaks_escaner: EscanerGitleaks,
    codeql_analyzer: CodeQLAnalyzer,
) -> dict:
    nombre = repo_entry["name"]
    etapas: dict[str, str] = {}
    LOGGER.info("[%s] Iniciando", nombre)

    # Etapa 1: Clone
    try:
        ok = _clonar_repo(repo_entry)
    except Exception as e:
        ok = False
        LOGGER.error("[%s] Clone: error inesperado: %s", nombre, e)

    if not ok:
        etapas["clone"] = "error"
        LOGGER.error("[%s] Clone fallo, omitiendo etapas restantes", nombre)
        return {"nombre": nombre, "etapas": etapas}
    etapas["clone"] = "ok"

    repo_path = str((RUTA_REPOS / nombre).relative_to(RAIZ))
    ruta_repo = RUTA_REPOS / nombre

    # Etapa 2: SBOM
    try:
        sbom_data = sbom_gen.generate_sbom(repo_path)
        sbom_gen.save_sbom(nombre, sbom_data)
        sbom_gen._eliminar_archivos_legados(nombre)
        etapas["sbom"] = "ok"
        LOGGER.info("[%s] SBOM generado", nombre)
    except Exception as e:
        sbom_gen._eliminar_archivos_parciales(nombre)
        etapas["sbom"] = "error"
        LOGGER.error("[%s] SBOM: %s", nombre, e)

    # Etapa 3: Gitleaks
    try:
        hallazgos = gitleaks_escaner.ejecutar_gitleaks(ruta_repo)
        gitleaks_escaner.guardar_resultado(nombre, hallazgos)
        etapas["gitleaks"] = "ok"
        LOGGER.info("[%s] Gitleaks completado (%s hallazgos)", nombre, len(hallazgos))
    except Exception as e:
        gitleaks_escaner._eliminar_archivos_parciales(nombre)
        etapas["gitleaks"] = "error"
        LOGGER.error("[%s] Gitleaks: %s", nombre, e)

    # Etapa 4: Grype
    try:
        grype_output = grype_analyzer.run_grype(repo_path)
        analysis = grype_analyzer.parse_grype_output(grype_output)
        grype_analyzer.save_analysis(nombre, grype_output, analysis)
        etapas["grype"] = "ok"
        LOGGER.info("[%s] Grype completado", nombre)
    except Exception as e:
        grype_analyzer._eliminar_archivos_parciales(nombre)
        etapas["grype"] = "error"
        LOGGER.error("[%s] Grype: %s", nombre, e)

    # Etapa 5: CodeQL — semáforo limita concurrencia para no saturar RAM
    with _SEM_CODEQL:
        try:
            sarif_data = codeql_analyzer.run_codeql(repo_path)
            analysis = codeql_analyzer.parse_sarif(sarif_data)
            codeql_analyzer.save_analysis(nombre, analysis)
            etapas["codeql"] = "ok"
            LOGGER.info("[%s] CodeQL completado", nombre)
        except Exception as e:
            codeql_analyzer._eliminar_archivos_parciales(nombre)
            etapas["codeql"] = "error"
            LOGGER.error("[%s] CodeQL: %s", nombre, e)

    LOGGER.info("[%s] Finalizado | %s", nombre, etapas)
    return {"nombre": nombre, "etapas": etapas}


def _correr_etapas() -> int:
    LOGGER.info("=== Iniciando pipeline de analisis ===")

    LOGGER.info("Obteniendo repositorios desde GitHub...")
    if not _ejecutar_subprocess("obtain_repositories.py"):
        LOGGER.error("Fallo al obtener repositorios")
        return 1

    if not RUTA_REPOS_JSON.exists():
        LOGGER.error("No se encontro %s", RUTA_REPOS_JSON)
        return 1

    repos_data = json.loads(RUTA_REPOS_JSON.read_text(encoding="utf-8"))
    repos = repos_data.get("repositories", [])
    if not repos:
        LOGGER.error("No hay repositorios en repos.json")
        return 1

    LOGGER.info(
        "Repositorios: %s | Workers generales: %s | Workers CodeQL: %s",
        len(repos), WORKERS, _WORKERS_CODEQL,
    )
    LOGGER.info("Orden de etapas por repo: clone -> sbom -> gitleaks -> grype -> codeql")

    RUTA_RESULTADOS.mkdir(parents=True, exist_ok=True)

    sbom_gen = SBOMGenerator(str(RUTA_REPOS), str(RUTA_RESULTADOS))
    sbom_gen.syft_path = sbom_gen._resolver_syft()

    grype_analyzer = GrypeAnalyzer(str(RUTA_REPOS), str(RUTA_RESULTADOS))
    grype_analyzer.grype_path = grype_analyzer._resolver_grype()

    gitleaks_escaner = EscanerGitleaks(str(RUTA_RESULTADOS), str(RUTA_RESULTADOS))
    gitleaks_escaner.gitleaks_path = gitleaks_escaner._resolver_gitleaks()

    codeql_analyzer = CodeQLAnalyzer(str(RUTA_REPOS), str(RUTA_RESULTADOS))
    codeql_analyzer.codeql_path = codeql_analyzer._resolver_codeql()

    resultados: list[dict] = []
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futuros = {
            executor.submit(
                _procesar_repo,
                repo,
                sbom_gen,
                grype_analyzer,
                gitleaks_escaner,
                codeql_analyzer,
            ): repo["name"]
            for repo in repos
        }
        for futuro in as_completed(futuros):
            nombre = futuros[futuro]
            try:
                resultado = futuro.result()
                resultados.append(resultado)
            except Exception as e:
                LOGGER.error("Worker | %s: error fatal inesperado: %s", nombre, e)
                resultados.append({"nombre": nombre, "etapas": {"pipeline": "error_fatal"}})

    ETAPAS = ["clone", "sbom", "gitleaks", "grype", "codeql"]
    LOGGER.info("=" * 70)
    LOGGER.info("RESUMEN DEL PIPELINE")
    LOGGER.info("%-30s %s", "Repositorio", "  ".join(f"{e:>8}" for e in ETAPAS))
    LOGGER.info("-" * 70)
    for r in sorted(resultados, key=lambda x: x["nombre"]):
        estado = r["etapas"]
        cols = "  ".join(
            f"{'ok':>8}" if estado.get(e) == "ok"
            else f"{'ERROR':>8}" if estado.get(e) == "error"
            else f"{'-':>8}"
            for e in ETAPAS
        )
        LOGGER.info("%-30s %s", r["nombre"], cols)
    LOGGER.info("=" * 70)
    LOGGER.info("=== Pipeline finalizado ===")
    return 0


def main() -> int:
    dashboard = _lanzar_dashboard()
    codigo = 0
    try:
        codigo = _correr_etapas()
    except KeyboardInterrupt:
        LOGGER.info("Interrumpido por el usuario")
        codigo = 130

    if dashboard is not None and dashboard.poll() is None:
        puerto = os.environ.get("PORT", "4173")
        LOGGER.info("=" * 60)
        LOGGER.info("Dashboard sigue activo en http://localhost:%s", puerto)
        LOGGER.info("Pulsa Ctrl-C para detenerlo y salir.")
        LOGGER.info("=" * 60)
        try:
            dashboard.wait()
        except KeyboardInterrupt:
            pass
        finally:
            _detener_dashboard(dashboard)

    return codigo


if __name__ == "__main__":
    raise SystemExit(main())

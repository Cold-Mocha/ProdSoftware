from __future__ import annotations

import logging
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
SCRIPTS = RAIZ / "scripts"
sys.path.insert(0, str(SCRIPTS))

from generate_sboms import SBOMGenerator
from generate_grype import GrypeAnalyzer
from generate_gitleaks import EscanerGitleaks, SUFIJO_SBOM
from generate_codeql import CodeQLAnalyzer

RUTA_REPOS = RAIZ / "data" / "repos"
RUTA_RESULTADOS = RAIZ / "data" / "results"
WORKERS_GENERALES = 10
WORKERS_CODEQL = 3

if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)


def _ejecutar_subprocess(script: str) -> bool:
    resultado = subprocess.run(
        [sys.executable, str(SCRIPTS / script)],
        cwd=str(RAIZ),
        check=False,
    )
    return resultado.returncode == 0


def _ejecutar_en_paralelo(fn, items, workers: int) -> tuple[int, int]:
    exitosos = 0
    errores = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futuros = {executor.submit(fn, item): item for item in items}
        for futuro in as_completed(futuros):
            try:
                if futuro.result():
                    exitosos += 1
                else:
                    errores += 1
            except Exception as error:
                LOGGER.error("Error inesperado en worker: %s", error)
                errores += 1
    return exitosos, errores


def _ejecutar_etapa_sbom(repositorios: list[str]) -> tuple[int, int]:
    generador = SBOMGenerator(str(RUTA_REPOS), str(RUTA_RESULTADOS))
    generador.syft_path = generador._resolver_syft()
    RUTA_RESULTADOS.mkdir(parents=True, exist_ok=True)

    def procesar(repo_path: str) -> bool:
        ruta_repo = generador.project_root / repo_path
        try:
            sbom_data = generador.generate_sbom(repo_path)
            generador.save_sbom(ruta_repo.name, sbom_data)
            generador._eliminar_archivos_legados(ruta_repo.name)
            return True
        except Exception as error:
            generador._eliminar_archivos_parciales(ruta_repo.name)
            LOGGER.error("SBOM | %s: %s", repo_path, error)
            return False

    return _ejecutar_en_paralelo(procesar, repositorios, WORKERS_GENERALES)


def _ejecutar_etapa_grype(repositorios: list[str]) -> tuple[int, int]:
    analizador = GrypeAnalyzer(str(RUTA_REPOS), str(RUTA_RESULTADOS))
    analizador.grype_path = analizador._resolver_grype()
    RUTA_RESULTADOS.mkdir(parents=True, exist_ok=True)

    def procesar(repo_path: str) -> bool:
        ruta_repo = analizador.project_root / repo_path
        try:
            grype_output = analizador.run_grype(repo_path)
            analysis = analizador.parse_grype_output(grype_output)
            analizador.save_analysis(ruta_repo.name, grype_output, analysis)
            return True
        except Exception as error:
            analizador._eliminar_archivos_parciales(ruta_repo.name)
            LOGGER.error("Grype | %s: %s", repo_path, error)
            return False

    return _ejecutar_en_paralelo(procesar, repositorios, WORKERS_GENERALES)


def _ejecutar_etapa_gitleaks(sboms: list[Path]) -> tuple[int, int]:
    escaner = EscanerGitleaks(str(RUTA_RESULTADOS), str(RUTA_RESULTADOS))
    escaner.gitleaks_path = escaner._resolver_gitleaks()
    RUTA_RESULTADOS.mkdir(parents=True, exist_ok=True)

    def procesar(ruta_sbom: Path) -> bool:
        nombre_repo = ruta_sbom.name[: -len(SUFIJO_SBOM)]
        try:
            ruta_repo = escaner.obtener_ruta_repo(ruta_sbom)
            if not ruta_repo.exists():
                LOGGER.warning("Gitleaks | Repositorio no encontrado: %s", ruta_repo)
                return False
            hallazgos = escaner.ejecutar_gitleaks(ruta_repo)
            escaner.guardar_resultado(nombre_repo, hallazgos)
            return True
        except Exception as error:
            escaner._eliminar_archivos_parciales(nombre_repo)
            LOGGER.error("Gitleaks | %s: %s", nombre_repo, error)
            return False

    return _ejecutar_en_paralelo(procesar, sboms, WORKERS_GENERALES)


def _ejecutar_etapa_codeql(repositorios: list[str]) -> tuple[int, int]:
    analizador = CodeQLAnalyzer(str(RUTA_REPOS), str(RUTA_RESULTADOS))
    analizador.codeql_path = analizador._resolver_codeql()
    RUTA_RESULTADOS.mkdir(parents=True, exist_ok=True)

    def procesar(repo_path: str) -> bool:
        ruta_repo = analizador.project_root / repo_path
        try:
            sarif_data = analizador.run_codeql(repo_path)
            analysis = analizador.parse_sarif(sarif_data)
            analizador.save_analysis(ruta_repo.name, analysis)
            return True
        except Exception as error:
            analizador._eliminar_archivos_parciales(ruta_repo.name)
            LOGGER.error("CodeQL | %s: %s", repo_path, error)
            return False

    return _ejecutar_en_paralelo(procesar, repositorios, WORKERS_CODEQL)


def main() -> int:
    LOGGER.info("=== Iniciando pipeline de analisis ===")

    LOGGER.info("[1/6] Obteniendo repositorios desde GitHub...")
    if not _ejecutar_subprocess("obtain_repositories.py"):
        LOGGER.error("Fallo al obtener repositorios")
        return 1

    LOGGER.info("[2/6] Clonando repositorios...")
    if not _ejecutar_subprocess("add_submodules.py"):
        LOGGER.error("Fallo al clonar repositorios")
        return 1

    if not RUTA_REPOS.exists() or not any(RUTA_REPOS.iterdir()):
        LOGGER.error("No se encontraron repositorios en %s", RUTA_REPOS)
        return 1

    repositorios = sorted(
        str(ruta.relative_to(RAIZ))
        for ruta in RUTA_REPOS.iterdir()
        if ruta.is_dir()
    )
    LOGGER.info("Repositorios a procesar: %s", len(repositorios))

    LOGGER.info("[3/6] Generando SBOMs (%s workers)...", WORKERS_GENERALES)
    exitosos, errores = _ejecutar_etapa_sbom(repositorios)
    LOGGER.info("SBOMs | exitosos=%s | errores=%s", exitosos, errores)

    LOGGER.info("[4/6] Ejecutando Grype (%s workers)...", WORKERS_GENERALES)
    exitosos, errores = _ejecutar_etapa_grype(repositorios)
    LOGGER.info("Grype | exitosos=%s | errores=%s", exitosos, errores)

    LOGGER.info("[5/6] Ejecutando Gitleaks (%s workers)...", WORKERS_GENERALES)
    sboms = sorted(RUTA_RESULTADOS.glob(f"*{SUFIJO_SBOM}"))
    exitosos, errores = _ejecutar_etapa_gitleaks(sboms)
    LOGGER.info("Gitleaks | exitosos=%s | errores=%s", exitosos, errores)

    LOGGER.info("[6/6] Ejecutando CodeQL (%s workers)...", WORKERS_CODEQL)
    exitosos, errores = _ejecutar_etapa_codeql(repositorios)
    LOGGER.info("CodeQL | exitosos=%s | errores=%s", exitosos, errores)

    LOGGER.info("=== Pipeline finalizado ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

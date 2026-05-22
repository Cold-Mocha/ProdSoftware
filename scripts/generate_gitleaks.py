from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
from pathlib import Path


RUTA_BASE = Path(__file__).resolve().parents[1]
RUTA_RESULTADOS_POR_DEFECTO = RUTA_BASE / "data" / "results"
SUFIJO_SBOM = "-sbom.json"
SUFIJO_GITLEAKS = "-gitleaks.json"
MENSAJE_GITLEAKS_NO_INSTALADO = (
    "Gitleaks CLI no esta instalado. Instalar desde https://github.com/gitleaks/gitleaks"
)


if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)


class EscanerGitleaks:
    def __init__(self, results_path: str, output_path: str):
        self.results_path = Path(results_path).expanduser().resolve()
        self.output_path = Path(output_path).expanduser().resolve()
        self.raiz_proyecto = Path(__file__).resolve().parents[1]
        self.gitleaks_bin = "gitleaks"
        self.dry_run = False
        self.gitleaks_path: str | None = None

    def descubrir_sboms(self) -> list[Path]:
        self._validar_directorio_resultados()
        sboms = sorted(self.results_path.glob(f"*{SUFIJO_SBOM}"))
        if not sboms:
            LOGGER.warning("No se encontraron SBOMs en %s", self.results_path)
        return sboms

    def obtener_ruta_repo(self, ruta_sbom: Path) -> Path:
        datos = json.loads(ruta_sbom.read_text(encoding="utf-8"))
        source = datos.get("source", {})
        target = source.get("target", {})
        ruta_str = target.get("path", "") if isinstance(target, dict) else str(target)

        if ruta_str:
            ruta_repo = Path(ruta_str)
            if ruta_repo.exists():
                return ruta_repo

        nombre_repo = ruta_sbom.name[: -len(SUFIJO_SBOM)]
        return self.raiz_proyecto / "data" / "repos" / nombre_repo

    def ejecutar_gitleaks(self, ruta_repo: Path) -> list[dict]:
        if not ruta_repo.exists():
            raise FileNotFoundError(f"El repositorio no existe: {ruta_repo}")

        if not ruta_repo.is_dir():
            raise NotADirectoryError(f"La ruta no es un directorio: {ruta_repo}")

        gitleaks_path = self.gitleaks_path or self._resolver_gitleaks()
        es_repo_git = (ruta_repo / ".git").exists()
        ruta_temp = self.output_path / f"_{ruta_repo.name}_tmp.json"
        self.output_path.mkdir(parents=True, exist_ok=True)

        comando = [
            gitleaks_path,
            "detect",
            "--source", str(ruta_repo),
            "--report-format", "json",
            "--report-path", str(ruta_temp),
        ]

        if not es_repo_git:
            comando.append("--no-git")

        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            check=False,
        )

        hallazgos: list[dict] = []
        if ruta_temp.exists():
            contenido = ruta_temp.read_text(encoding="utf-8").strip()
            ruta_temp.unlink()
            if contenido:
                try:
                    parsed = json.loads(contenido)
                    hallazgos = parsed if isinstance(parsed, list) else []
                except json.JSONDecodeError:
                    hallazgos = []

        if resultado.returncode > 1:
            raise RuntimeError(
                f"Gitleaks termino con error (codigo {resultado.returncode}): {resultado.stderr.strip()}"
            )

        return hallazgos

    def guardar_resultado(self, nombre_repo: str, hallazgos: list[dict]) -> Path:
        if not nombre_repo:
            raise ValueError("El nombre del repositorio no puede estar vacio.")

        self.output_path.mkdir(parents=True, exist_ok=True)

        resultado = {
            "repositorio": nombre_repo,
            "total_hallazgos": len(hallazgos),
            "hallazgos": hallazgos,
        }

        ruta_salida = self.output_path / f"{nombre_repo}{SUFIJO_GITLEAKS}"
        ruta_salida.write_text(json.dumps(resultado, ensure_ascii=False, indent=2), encoding="utf-8")
        LOGGER.info("Resultado guardado en %s", ruta_salida.relative_to(self.raiz_proyecto))
        return ruta_salida

    def run(self):
        sboms = self.descubrir_sboms()
        self._validar_directorio_salida()

        if not sboms:
            return

        if not self.dry_run:
            self.gitleaks_path = self._resolver_gitleaks()
            LOGGER.info("Usando Gitleaks CLI: %s", self.gitleaks_path)

        self.output_path.mkdir(parents=True, exist_ok=True)

        repos_escaneados = 0
        archivos_generados = 0
        omitidos = 0
        errores = 0

        for indice, ruta_sbom in enumerate(sboms, start=1):
            nombre_repo = ruta_sbom.name[: -len(SUFIJO_SBOM)]
            LOGGER.info("[%s/%s] Procesando SBOM %s", indice, len(sboms), ruta_sbom.name)

            if self.dry_run:
                LOGGER.info(
                    "[%s/%s] Dry-run: se escanearia %s", indice, len(sboms), nombre_repo
                )
                omitidos += 1
                continue

            try:
                ruta_repo = self.obtener_ruta_repo(ruta_sbom)

                if not ruta_repo.exists():
                    LOGGER.warning(
                        "[%s/%s] Repositorio no encontrado: %s", indice, len(sboms), ruta_repo
                    )
                    omitidos += 1
                    continue

                hallazgos = self.ejecutar_gitleaks(ruta_repo)
                self.guardar_resultado(nombre_repo, hallazgos)
                repos_escaneados += 1
                archivos_generados += 1
                LOGGER.info("[%s/%s] Hallazgos detectados: %s", indice, len(sboms), len(hallazgos))

            except Exception as error:
                errores += 1
                self._eliminar_archivos_parciales(nombre_repo)
                LOGGER.error(
                    "[%s/%s] Error al procesar %s: %s", indice, len(sboms), nombre_repo, error
                )

        LOGGER.info(
            "Resumen final | total_sboms=%s | repos_escaneados=%s | archivos_generados=%s | omitidos=%s | errores=%s",
            len(sboms),
            repos_escaneados,
            archivos_generados,
            omitidos,
            errores,
        )

    def _validar_directorio_resultados(self):
        if not self.results_path.exists():
            raise FileNotFoundError(
                f"El directorio de resultados no existe: {self.results_path}"
            )

        if not self.results_path.is_dir():
            raise NotADirectoryError(
                f"La ruta de resultados no es un directorio: {self.results_path}"
            )

    def _validar_directorio_salida(self):
        if self.output_path.exists() and not self.output_path.is_dir():
            raise NotADirectoryError(
                f"La ruta de salida no es un directorio: {self.output_path}"
            )

    def _resolver_gitleaks(self) -> str:
        ruta = shutil.which(self.gitleaks_bin)
        if not ruta:
            raise RuntimeError(MENSAJE_GITLEAKS_NO_INSTALADO)
        return ruta

    def _eliminar_archivos_parciales(self, nombre_repo: str):
        ruta = self.output_path / f"{nombre_repo}{SUFIJO_GITLEAKS}"
        if ruta.exists():
            ruta.unlink()


def _construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ejecuta Gitleaks sobre los repositorios de los SBOMs generados."
    )
    parser.add_argument(
        "--results-path",
        default=str(RUTA_RESULTADOS_POR_DEFECTO),
        help="Ruta al directorio que contiene los SBOMs generados.",
    )
    parser.add_argument(
        "--output-path",
        default=str(RUTA_RESULTADOS_POR_DEFECTO),
        help="Ruta al directorio donde se guardaran los resultados de Gitleaks.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra que repositorios se escanearian sin ejecutar Gitleaks.",
    )
    return parser


def main() -> int:
    parser = _construir_parser()
    args = parser.parse_args()

    escaner = EscanerGitleaks(args.results_path, args.output_path)
    escaner.dry_run = args.dry_run

    try:
        escaner.run()
    except Exception as error:
        LOGGER.error("%s", error)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

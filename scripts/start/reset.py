from __future__ import annotations

import logging
import shutil
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]

OBJETIVOS = [
    RAIZ / "data" / "repos",
    RAIZ / "data" / "results",
    RAIZ / "data" / "repos.json",
]

if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
LOGGER = logging.getLogger(__name__)


def _confirmar() -> bool:
    LOGGER.warning("Se eliminaran los siguientes elementos:")
    for objetivo in OBJETIVOS:
        existe = objetivo.exists()
        estado = "existe" if existe else "no existe"
        LOGGER.warning("  %s [%s]", objetivo.relative_to(RAIZ), estado)

    respuesta = input("\n¿Confirmar reset? Escribe 'si' para continuar: ").strip().lower()
    return respuesta == "si"


def _eliminar(objetivo: Path) -> bool:
    if not objetivo.exists():
        LOGGER.info("Omitido (no existe): %s", objetivo.relative_to(RAIZ))
        return True

    try:
        if objetivo.is_dir():
            shutil.rmtree(objetivo)
        else:
            objetivo.unlink()
        LOGGER.info("Eliminado: %s", objetivo.relative_to(RAIZ))
        return True
    except Exception as error:
        LOGGER.error("Error al eliminar %s: %s", objetivo.relative_to(RAIZ), error)
        return False


def main() -> int:
    LOGGER.info("=== Reset del pipeline ===")

    if not _confirmar():
        LOGGER.info("Reset cancelado.")
        return 0

    errores = 0
    for objetivo in OBJETIVOS:
        if not _eliminar(objetivo):
            errores += 1

    if errores:
        LOGGER.error("Reset completado con %s error(es).", errores)
        return 1

    LOGGER.info("=== Reset completado. El pipeline puede ejecutarse desde cero. ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

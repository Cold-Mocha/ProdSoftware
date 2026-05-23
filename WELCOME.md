# Bienvenida

Este repositorio contiene el material desplegable de **Produccion de Software EMI305**.

## Primeros
1. Abre el repositorio en VS Code.
2. Ejecuta `Dev Containers: Rebuild and Reopen in Container`.
3. Espera a que el contenedor termine de instalar dependencias y herramientas.
4. Usa el kernel `Python (produccion-software-emi305)` para ejecutar notebooks.

## Herramientas incluidas

El Dev Container instala:

- Python 3.11
- uv
- JupyterLab
- Syft
- Grype
- CodeQL CLI
- Node.js 20

## Repositorios de ejemplo

Los repositorios usados por los notebooks y scripts se declaran en `data/repos.json`.
Para clonarlos o actualizarlos:

```bash
uv run python scripts/add_submodules.py
```

## Analisis disponibles

```bash
uv run python scripts/generate_sboms.py
uv run python scripts/generate_codeql.py
uv run python scripts/generate_grype.py
```

Tambien puedes ejecutar los notebooks en:

- `nbs/sbom/generacion_sbom.ipynb`
- `nbs/vuln/generacion_codeql.ipynb`
- `nbs/vuln/generacion_grype.ipynb`

Los resultados se escriben en `data/results/`.

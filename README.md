# Produccion de Software EMI305

Repositorio del curso **Produccion de Software EMI305** con un modulo practico de seguridad de software.

## 1. Contexto del analisis

Se analizaron varios repositorios de ejemplo del ecosistema Express definidos en `data/repos.json`:
`express`, `multer`, `morgan`, `session`, `cors`, `body-parser`, `expressjs.com`, `compression`, `csurf` y `cookie-parser`.

Antes de este resumen ya se venian ejecutando tareas de seguridad con:

- generacion de SBOMs con Syft
- analisis de vulnerabilidades con Grype
- analisis de codigo con CodeQL
- deteccion de secretos con Gitleaks
- almacen de resultados en `data/results/`

## 2. Vulnerabilidades encontradas

Hallazgos principales:

Nota de clasificacion: un secreto dentro de un fixture de prueba no es automaticamente una vulnerabilidad explotable. En este analisis se registra como hallazgo que debe verificarse: si es sintetico y solo se usa localmente, baja la prioridad; si fue reutilizado fuera de tests, pasa a ser vulnerabilidad real.

- `expressjs.com`: 15 vulnerabilidades en dependencias (`vite`, `picomatch`, `astro`, `defu`, `yaml`, `postcss`, `devalue`, etc.) y 1 secreto tipo API key en `_data/docsearch.yml`.
- `session`: 3 hallazgos de Gitleaks por claves privadas en `test/fixtures/server.key`; al ser fixtures, requieren validacion antes de tratarlos como vulnerabilidades reales.
- `morgan`: 2 hallazgos de Gitleaks por claves privadas en `test/fixtures/server.key`; al ser fixtures, requieren validacion antes de tratarlos como vulnerabilidades reales.
- `express`: 34 hallazgos de CodeQL, sobre todo en ejemplos y demos; destacan cookies sin SSL, logs en texto claro y trazas sensibles.
- `body-parser`: 13 hallazgos de CodeQL; destacan XSS reflejado, exposición de stack trace y log injection en tests/codigo.
- `multer`: 1 hallazgo de CodeQL.
- `cors`: 1 hallazgo de CodeQL.

Repos con cero hallazgos relevantes en los artefactos revisados: `compression`, `cookie-parser`, `csurf` y varios de los scans de Grype sobre dependencias de libreria.

## 3. Clasificacion segun vector de ataque

- Dependencias y codigo fuente
  - Grype en `expressjs.com` por paquetes vulnerables.
  - CodeQL en `express`, `body-parser`, `multer` y `cors` por patrones inseguros en codigo y ejemplos.

- Pipelines de CI/CD
  - No se identificaron hallazgos directos en los reportes revisados.
  - El riesgo sigue presente por la publicacion del sitio y el uso de automatizacion de analisis.

- Humanos
  - Gitleaks en `session`, `morgan` y `expressjs.com` por secretos o fixtures sensibles versionados en el repositorio.

## 4. Analisis usando el ciclo Conozco -> Verifico -> Evidencio -> Decido y Actuo

### Secretos y fixtures detectados

- Conozco: hay claves privadas en fixtures y una API key versionada en el repo.
- Verifico: Gitleaks marca ubicacion exacta, tipo de secreto y commit de origen; luego se valida si el dato es real, sintetico, reutilizado o solo de prueba.
- Evidencio: `data/results/session-gitleaks.json`, `morgan-gitleaks.json`, `expressjs.com-gitleaks.json`.
- Decido y Actuo: si el secreto es real o reutilizable, rotar y borrar historico si aplica; si es fixture sintetico, documentar falso positivo controlado o reemplazarlo por generacion local durante tests.

### Dependencias vulnerables

- Conozco: `expressjs.com` arrastra dependencias con CVE/GHSA activas.
- Verifico: Grype reporta 15 vulnerabilidades con severidad alta/media/baja y versiones corregidas.
- Evidencio: `data/results/expressjs.com-grype.json`.
- Decido y Actuo: actualizar versiones, reconstruir SBOM y repetir escaneo hasta dejar el arbol sin hallazgos criticos/altos.

### Patrones inseguros en codigo

- Conozco: hay ejemplos con cookies sin SSL, logs con datos sensibles y XSS/log injection en tests o ejemplos.
- Verifico: CodeQL apunta archivo, linea y regla afectada.
- Evidencio: `express-codeql.json`, `body-parser-codeql.json`, `multer-codeql.json`, `cors-codeql.json`.
- Decido y Actuo: corregir patrones, reforzar linting/seguridad en PRs y separar mejor ejemplos de codigo de produccion.

## 5. Priorizacion de vulnerabilidades

1. Secretos confirmados como reales o reutilizables, especialmente la API key de `expressjs.com`
   - severidad alta por impacto directo
   - explotacion facil
   - evidencia concreta y accion inmediata: rotacion y eliminacion

2. Vulnerabilidades en dependencias de `expressjs.com`
   - varias son high severity
   - afectan superficie publica del sitio
   - hay fix versions disponibles

3. Hallazgos de CodeQL en codigo fuente
   - prioridad media/alta segun ubicacion real
   - sube si toca codigo ejecutable o caminos publicos
   - baja si solo vive en tests o ejemplos, aunque igual se corrige

4. Claves privadas en fixtures de `session` y `morgan`
   - no son vulnerabilidad confirmada si solo sirven para pruebas locales
   - deben validarse para descartar reutilizacion fuera de tests
   - se pueden mantener como falso positivo documentado o reemplazar por claves generadas en runtime de test

## 6. Acciones propuestas

- rotar y revocar secretos confirmados como reales o reutilizados
- limpiar historial git si un secreto real ya se publico
- documentar fixtures validos como falso positivo controlado o generarlos durante tests
- mover credenciales a secretos gestionados por entorno/CI
- actualizar dependencias vulnerables de `expressjs.com`
- re-ejecutar Grype, CodeQL y Gitleaks tras cada correccion
- reforzar revisiones de PR para evitar cookies inseguras, logs sensibles y XSS
- añadir controles preventivos en CI para bloquear nuevos secretos y vulnerabilidades criticas

## 7. Evidencia utilizada

- `data/repos.json`: inventario de repositorios analizados
- `data/results/*-grype.json`: resumen de vulnerabilidades por dependencia
- `data/results/*-codeql.json`: hallazgos de codigo con ruta, linea y regla
- `data/results/*-gitleaks.json`: secretos detectados con ubicacion y commit origen
- `data/results/*_temp.sarif`: salidas temporales de escaneo
- scripts en `scripts/`: generacion de SBOM, CodeQL y Grype

## 8. Conclusiones

El analisis muestra que la reduccion de riesgo debe enfocarse primero en secretos confirmados como reales, luego en dependencias vulnerables y despues en hallazgos de codigo segun su exposicion. Esta decision evita gastar esfuerzo en falsos positivos, como fixtures sinteticos de prueba, sin ignorar que deben verificarse y documentarse.

Las acciones propuestas reducen el riesgo porque:

- limitan exposicion de credenciales mediante rotacion, revocacion y uso de secretos gestionados
- reducen superficie de ataque actualizando dependencias con versiones corregidas
- mejoran calidad defensiva del codigo corrigiendo patrones inseguros detectados por CodeQL
- fortalecen el proceso futuro con controles en CI para bloquear nuevos secretos y vulnerabilidades criticas

En sintesis, la propuesta combina correccion inmediata, validacion de evidencia y prevencion continua para que el sistema analizado quede menos expuesto y mas controlado.

## Inicio rapido

Con Docker y VS Code instalados, abre este repositorio en un Dev Container. El contenedor ejecuta `uv sync`, registra el kernel de Jupyter y prepara las herramientas de seguridad.

Para preparar los repositorios de ejemplo:

```bash
uv run python scripts/add_submodules.py
```

Para ejecutar los analisis:

```bash
uv run python scripts/generate_sboms.py
uv run python scripts/generate_codeql.py
uv run python scripts/generate_grype.py
```

Los resultados se guardan en `data/results/`.

## Sitio del curso

El sitio Quarto se construye desde `nbs/`:

```bash
cd nbs
uv run quarto render
```

La configuracion de publicacion apunta a:

<https://dci-courses.github.io/produccion_software_emi305/>

## Estructura

```text
.
├── .devcontainer/       # Entorno reproducible del curso
├── .github/workflows/   # CI y despliegue
├── data/
│   ├── book/            # Material base del curso
│   ├── papers/          # Lecturas de apoyo
│   ├── repos/           # Repositorios de ejemplo clonados localmente
│   ├── results/         # Resultados de referencia y salidas regenerables
│   └── repos.json       # Configuracion de repositorios de ejemplo
├── nbs/                 # Sitio Quarto, notebooks y lecturas
├── scripts/             # Automatizacion de seguridad
├── pyproject.toml       # Dependencias Python
└── uv.lock              # Lockfile de dependencias
```

## Validacion local

```bash
python3 -m compileall scripts
python3 scripts/add_submodules.py --dry-run
python3 scripts/generate_sboms.py --dry-run
python3 scripts/generate_codeql.py --dry-run
python3 scripts/generate_grype.py --dry-run
```

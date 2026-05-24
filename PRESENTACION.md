# Presentacion del analisis de vulnerabilidades

> Resumen para exposicion de maximo 10 minutos. Este documento refiere al informe completo en [`README.md`](README.md) y no busca repetirlo entero.

## Introduccion

Esta presentacion comunica las decisiones principales del analisis de seguridad: que se reviso, que riesgos aparecen, que evidencia los respalda y que acciones reducen el riesgo.

Guion recomendado:

| Tiempo | Seccion | Enfoque |
| --- | --- | --- |
| 1 min | Introduccion y contexto | Que se analizo y con que herramientas. |
| 1 min | Alcance y objetivos | Que se busca decidir, no solo listar hallazgos. |
| 2 min | Desarrollo | Metodo y evidencia usada. |
| 2 min | Hallazgos | Vulnerabilidades y hallazgos principales. |
| 2 min | Evaluacion de riesgos | Priorizacion y matriz de riesgo. |
| 1 min | Mitigaciones | Acciones concretas. |
| 1 min | Cierre | Como baja el riesgo. |

## Contexto

Express es un framework web minimalista para Node.js. Se usa para construir APIs, aplicaciones web y middleware HTTP. Los repositorios analizados pertenecen a su ecosistema: algunos son el nucleo del framework, otros son middlewares usados para manejar sesiones, cookies, CORS, compresion, formularios, logs y documentacion.

Repositorios definidos en `data/repos.json`:

| Repositorio | De que trata | Rol dentro del ecosistema |
| --- | --- | --- |
| `express` | Framework web principal para Node.js. | Nucleo para crear rutas, middlewares y aplicaciones HTTP. |
| `multer` | Middleware para manejar `multipart/form-data`. | Se usa para subida de archivos y formularios con archivos. |
| `morgan` | Middleware de logging HTTP. | Registra peticiones para auditoria, debug y monitoreo. |
| `session` | Middleware de sesiones para Express. | Maneja estado de usuario mediante cookies y almacenamiento de sesion. |
| `cors` | Middleware para configurar CORS. | Controla que origenes pueden consumir recursos HTTP. |
| `body-parser` | Middleware para parsear cuerpos de request. | Procesa JSON, texto, raw y formularios urlencoded. |
| `expressjs.com` | Sitio web oficial de Express. | Publica documentacion y contenido del proyecto. |
| `compression` | Middleware de compresion HTTP. | Reduce tamano de respuestas con gzip/brotli cuando aplica. |
| `csurf` | Middleware historico de proteccion CSRF. | Ayuda a mitigar ataques Cross-Site Request Forgery. |
| `cookie-parser` | Middleware para parsear cookies. | Lee y firma cookies recibidas en requests. |

Herramientas usadas:

- Syft para SBOM
- Grype para vulnerabilidades en dependencias
- CodeQL para analisis de codigo fuente
- Gitleaks para secretos y credenciales versionadas

Referencia completa: [`README.md`](README.md#1-contexto-del-analisis).

## Alcance y objetivos

Alcance:

- revisar dependencias y codigo fuente
- revisar evidencia generada por herramientas de seguridad
- clasificar hallazgos por vector de ataque
- proponer acciones de gestion de riesgo

Objetivos:

- identificar hallazgos relevantes
- separar vulnerabilidades reales de falsos positivos o fixtures
- priorizar segun severidad, exposicion, explotabilidad, impacto y evidencia
- proponer mitigaciones concretas

## Desarrollo

El analisis siguio este criterio:

1. Conocer inventario y componentes con `data/repos.json` y SBOMs.
2. Verificar dependencias con Grype.
3. Verificar codigo con CodeQL.
4. Verificar secretos con Gitleaks.
5. Evidenciar cada decision con archivos en `data/results/`.
6. Decidir acciones segun riesgo real, no solo por cantidad de hallazgos.

Evidencia clave:

- `data/results/expressjs.com-grype.json`
- `data/results/*-codeql.json`
- `data/results/*-gitleaks.json`
- `data/results/*-sbom.json`

Referencia completa: [`README.md`](README.md#7-evidencia-utilizada).

## Hallazgos

Hallazgos principales:

- `expressjs.com`: 15 vulnerabilidades en dependencias y 1 API key detectada.
- `session`: claves privadas detectadas en `test/fixtures/server.key`; son hallazgos a validar por ser fixtures.
- `morgan`: claves privadas detectadas en `test/fixtures/server.key`; tambien requieren validacion por ser fixtures.
- `express`: hallazgos CodeQL en ejemplos, como cookies sin SSL y logging sensible.
- `body-parser`: hallazgos CodeQL relacionados con XSS reflejado, stack trace y log injection.

Vectores asociados:

| Vector | Hallazgos asociados | Decision |
| --- | --- | --- |
| Dependencias y codigo fuente | Grype en `expressjs.com`; CodeQL en `express`, `body-parser`, `multer`, `cors` | Corregir segun exposicion y severidad. |
| Pipelines de CI/CD | Sin hallazgos directos en los reportes revisados | Agregar controles preventivos. |
| Humanos | Gitleaks en `expressjs.com`, `session`, `morgan` | Validar secretos; rotar si son reales. |

Decision importante: claves privadas en fixtures no son automaticamente vulnerabilidades explotables. Se validan antes de priorizarlas como riesgo alto.

Referencia completa: [`README.md`](README.md#2-vulnerabilidades-encontradas).

## Evaluacion de riesgos

Priorizacion propuesta:

1. Secretos confirmados como reales o reutilizables, especialmente la API key de `expressjs.com`.
2. Dependencias vulnerables de `expressjs.com`, porque hay severidad alta y versiones corregidas.
3. Hallazgos CodeQL en codigo fuente, segun si afectan codigo ejecutable, ejemplos o tests.
4. Claves privadas en fixtures de `session` y `morgan`, que deben validarse antes de tratarlas como vulnerabilidad real.

Matriz de riesgo:

| Hallazgo | Vector | Impacto | Probabilidad | Riesgo | Decision |
| --- | --- | --- | --- | --- | --- |
| API key en `expressjs.com` | Humanos | Alto | Media | Alto | Validar, rotar/revocar si es real y mover a secreto gestionado. |
| Dependencias vulnerables en `expressjs.com` | Dependencias | Alto | Media | Alto | Actualizar paquetes y repetir Grype. |
| CodeQL en `body-parser` | Codigo fuente | Medio | Media | Medio | Revisar si afecta codigo ejecutable; corregir XSS/log injection si aplica. |
| CodeQL en `express` | Codigo fuente | Medio | Baja/Media | Medio | Corregir ejemplos inseguros o documentarlos como no productivos. |
| Claves privadas en fixtures de `session` y `morgan` | Humanos | Bajo/Alto segun reutilizacion | Baja si son sinteticas | Bajo a Alto | Validar uso; documentar falso positivo o reemplazar por generacion local. |
| Pipelines CI/CD sin hallazgo directo | CI/CD | Medio | Baja | Bajo/Medio | Agregar controles preventivos. |

Referencia completa: [`README.md`](README.md#5-priorizacion-de-vulnerabilidades).

## Mitigaciones

Acciones propuestas:

Correctivas:

- rotar y revocar secretos confirmados como reales
- mover credenciales a secretos gestionados por entorno o CI
- documentar fixtures validos como falso positivo controlado o generarlos durante tests
- actualizar dependencias vulnerables de `expressjs.com`
- re-ejecutar Grype, CodeQL y Gitleaks tras los cambios
- corregir patrones inseguros de codigo cuando afecten rutas ejecutables o publicas

Preventivas:

- agregar pipeline de seguridad en pull requests, merges, tags y versiones previas a produccion
- comparar cada ejecucion contra un baseline para detectar vulnerabilidades nuevas
- bloquear secretos nuevos y vulnerabilidades critical/high sin excepcion aprobada
- mantener registro de falsos positivos, ignores permitidos y fixtures aceptados
- exigir revision humana para hallazgos en autenticacion, sesiones, cookies, CORS, subida de archivos, parsing de entrada o CI/CD
- revisar periodicamente permisos, tokens y configuracion de pipelines
- aplicar mejora continua: repetir analisis aunque la version actual quede corregida
- reabrir decisiones si aparece nueva evidencia o cambian dependencias, codigo, pipeline o contexto de amenaza

Referencia completa: [`README.md`](README.md#6-acciones-propuestas).
Documento preventivo: [`SEGURIDAD_PREVENTIVA.md`](SEGURIDAD_PREVENTIVA.md).

## Cierre

La propuesta reduce el riesgo porque enfoca el esfuerzo en lo mas importante:

- primero secretos reales y reutilizables
- despues dependencias vulnerables con parche disponible
- luego codigo segun exposicion real
- fixtures se validan, no se sobrerreaccionan
- CI/CD queda como barrera preventiva para evitar reincidencia antes de produccion
- falsos positivos e ignores quedan documentados, con dueño y fecha de revision
- mejora continua queda como directriz: el analisis no termina, se repite con cada version y con cada cambio relevante

Conclusion para exponer: no se trata de corregir todo al mismo tiempo ni de asumir que el sistema queda seguro para siempre. Se corrige primero lo de mayor impacto y se mantiene un ciclo continuo porque pueden aparecer riesgos nuevos que no eran visibles de forma inmediata o deterministica.

Referencia completa: [`README.md`](README.md#8-conclusiones).

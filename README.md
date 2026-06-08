# Análisis de seguridad en cadena de producción de software

**Estudiantes:** Daniela Díaz · David Millar
**Docente:** Mg. Pablo Valenzuela
**Asignatura:** Producción de Software (EMI305-1)
**Ultima Actualización:** 7 de Junio del 2026

Propuesta de gestión de vulnerabilidades para el ecosistema **Express (Node.js)**, organizada según el ciclo **Conozco → Verifico → Evidencio → Decido y Actúo** y los tres vectores de ataque: dependencias y código fuente, pipelines de CI/CD y humanos.

> **Pregunta central:** ¿Cómo debería gestionar el equipo las vulnerabilidades encontradas, considerando su origen, su evidencia y el nivel de riesgo que representan?

---

## 1. Contexto del análisis

Express es un **framework web minimalista para Node.js**, usado para construir APIs, aplicaciones web y middleware HTTP. Es una de las herramientas más influyentes del ecosistema JavaScript del lado del servidor y mantiene una presencia importante en proyectos backend por su madurez y comunidad.

Los repositorios analizados pertenecen a su ecosistema: algunos son el **núcleo del framework**, otros son **middlewares** (sesiones, cookies, CORS, compresión, formularios, logs) y también se incluye el **sitio web oficial del proyecto** (expressjs.com).

| Repositorio | Contenido | Rol dentro del ecosistema |
|---|---|---|
| `express` | Framework web principal para Node.js | Núcleo para crear rutas, middlewares y aplicaciones HTTP |
| `multer` | Middleware para `multipart/form-data` | Subida de archivos y formularios con archivos |
| `morgan` | Middleware de logging HTTP | Registra peticiones para auditoría, debug y monitoreo |
| `session` | Middleware de sesiones para Express | Maneja estado de usuario mediante cookies y almacenamiento de sesión |
| `cors` | Middleware para configurar CORS | Controla qué orígenes pueden consumir recursos HTTP |
| `body-parser` | Middleware para parsear cuerpos de request | Procesa JSON, texto, raw y formularios urlencoded |
| `expressjs.com` | Sitio web oficial de Express | Publica documentación y contenido del proyecto |
| `compression` | Middleware de compresión HTTP | Reduce tamaño de respuestas con gzip/brotli |
| `csurf` | Middleware histórico de protección CSRF | Ayuda a mitigar ataques Cross-Site Request Forgery |
| `cookie-parser` | Middleware para parsear cookies | Lee y firma cookies recibidas en requests |

*Tabla 1. Repositorios analizados, sus contenidos y su rol.*

### Alcance y objetivos

El alcance de la actividad fue: revisar dependencias y código fuente de los repositorios, revisar la evidencia generada por herramientas de seguridad, clasificar los hallazgos por vector de ataque y proponer acciones de gestión de riesgo.

En relación a lo anterior, se busca:

- Identificar hallazgos relevantes.
- Separar vulnerabilidades reales de falsos positivos o fixtures.
- Priorizar según severidad, exposición, explotabilidad, impacto y evidencia.
- Proponer mitigaciones correspondientes de carácter preventivo y correctivo.

El análisis previo se realizó con **Syft** (SBOM), **Grype** (dependencias), **CodeQL** (código) y **Gitleaks** (secretos). Los resultados se almacenan en `data/results/`.

---

## 2. Vulnerabilidades encontradas

Distribución de hallazgos por repositorio y herramienta (ver gráfico en `evidence/capturas/`):

| Repositorio | Secretos (Gitleaks) | Deps. (Grype) | Código (CodeQL) | Total |
|---|---:|---:|---:|---:|
| `express` | 0 | 0 | 34 | 34 |
| `expressjs.com` | 1 | 15 | 3 | 19 |
| `body-parser` | 0 | 0 | 13 | 13 |
| `session` | 3 | 0 | 4 | 7 |
| `morgan` | 2 | 0 | 0 | 2 |
| `multer` | 0 | 0 | 1 | 1 |
| `cors` | 0 | 0 | 1 | 1 |
| `csurf` | 0 | 0 | 0 | 0 |
| `cookie-parser` | 0 | 0 | 0 | 0 |
| `compression` | 0 | 0 | 0 | 0 |

*Tabla 2. Hallazgos por repositorio y herramienta.*

Los hallazgos se agrupan en cuatro tipos: **secretos expuestos**, **dependencias vulnerables**, **code smells de seguridad** (XSS) y **malas prácticas de configuración** (cifrado, control de acceso, autenticación y registros).

---

## 3. Clasificación según vector de ataque

Los hallazgos se consolidan en cinco grupos de riesgo (V01–V05), cada uno asociado a un vector:

| ID | Grupo de riesgo | Vector de ataque |
|---|---|---|
| V01 | Dependencias vulnerables | Dependencias y código fuente |
| V02 | Code smells de seguridad (XSS) | Dependencias y código fuente |
| V03 | Secretos expuestos | Humanos |
| V04 | Malas prácticas de configuración | Dependencias y código fuente |
| V05 | Malas prácticas en pipelines | Pipelines de CI/CD |

- **Dependencias y código fuente (V01, V02, V04):** Grype en `expressjs.com` por paquetes vulnerables; CodeQL en `express`, `expressjs.com`, `body-parser`, `session`, `multer` y `cors` por patrones inseguros.
- **Humanos (V03):** Gitleaks en `expressjs.com`, `session` y `morgan` por secretos y fixtures sensibles versionados.
- **Pipelines de CI/CD (V05):** el workflow `sync-orama.yml` ejecuta `orama-documents.mjs` (que procesa contenido de documentación) durante la integración del sitio; no hay hallazgo crítico directo, pero el flujo es un punto de riesgo a auditar.

---

## 4. Análisis: Conozco → Verifico → Evidencio → Decido y Actúo

### 4.1 Secretos expuestos (V03 — vector humano)

| Conozco | Verifico | Evidencio | Decido y Actúo |
|---|---|---|---|
| **5 claves privadas RSA** que podrían transparentar información encriptada. **1 API key de Algolia** en `expressjs.com` que permite acceso no autorizado al servicio. | Las claves RSA corresponden a archivos generados con propósitos de pruebas (fixtures de tests). La API key de Algolia tiene un formato aceptado por el servicio y es utilizada por el código. | `morgan-gitleaks.json`, `session-gitleaks.json`, `expressjs.com-gitleaks.json`. La API key está en `_data/docsearch.yml`; las claves privadas en `test/fixtures/server.key` de ambos repos. | Rotar API key de Algolia. Reemplazar las private keys por generación dinámica en tests. Limpiar historial con `git filter-repo`. Añadir Gitleaks en CI para prevenir futuras fugas. |

*Tabla 3. Hallazgos de secretos expuestos.*

### 4.2 Dependencias vulnerables (V01 — dependencias y código)

| Conozco | Verifico | Evidencio | Decido y Actúo |
|---|---|---|---|
| Grype detectó **15 vulnerabilidades activas** en `expressjs.com`: 7 High, 7 Medium, 1 Low. Paquetes como Vite 7.3.1, Picomatch 2.3.1/4.0.3, Astro 6.1.2, defu, etc. **Ninguna dependencia ha sido actualizada.** | **Vite 7.3.1** tiene 2 High: lectura de archivos arbitrarios vía WebSocket del dev server y bypass de `server.fs.deny` mediante queries en la URL (robo de código fuente, credenciales y archivos sensibles). **defu 6.1.4** tiene 1 High: prototype pollution vía `__proto__` en el argumento `defaults`, escalable a XSS o RCE. | `expressjs.com-grype.json`, con los 15 IDs, severidad, CVSS y versión con fix disponible. | Auditar dependencias y eliminar las que no se usan directamente. Actualizar a versiones con fixes (npm update / overrides para forzar versiones seguras en transitivas). Configurar Dependabot para automatizar actualizaciones. |

*Tabla 4. Hallazgos de dependencias vulnerables.*

### 4.3 Code smells de seguridad — XSS (V02 — dependencias y código)

| Conozco | Verifico | Evidencio | Decido y Actúo |
|---|---|---|---|
| CodeQL encontró **11 alertas XSS** activas en 3 repos: `expressjs.com` (3, en `SidebarVersionManager.ts` con `innerHTML` y `orama-documents.mjs` con sanitización incompleta — **afectan al sitio en producción**); `body-parser` (8, XSS reflejado en archivos de test); `session` (2, XSS reflejado en test). | `expressjs.com` usa `innerHTML` con datos que podrían contener HTML malicioso (renderiza versiones en el sidebar). En `body-parser` y `session` las alertas están en archivos de test, no en código desplegado. `orama-documents.mjs` tiene sanitización que permite inyectar `<script>` y se ejecuta en CI/CD (`sync-orama.yml`). | `body-parser-codeql.json`, `session-codeql.json`, `expressjs.com-codeql.json`, con regla, archivo y línea exacta. | Corregir `SidebarVersionManager.ts` reemplazando `innerHTML` por `textContent`. Corregir `orama-documents.mjs` usando librería de escape en vez de regex. Los tests quedan como **prioridad baja**, pero se establece política de no usar `innerHTML` ni en tests. Agregar regla ESLint `no-unsafe-innerHTML`. |

*Tabla 5. Hallazgos de code smells (XSS).*

### 4.4 Malas prácticas de configuración (V04 — dependencias y código)

| Conozco | Verifico | Evidencio | Decido y Actúo |
|---|---|---|---|
| **8 puntos** que afectan la capa de seguridad (cifrado, control de acceso, autenticación, registros): `express` (4: 3 cookies sin Secure y contraseñas en logs), `cors` (1: CORS abierto a cualquier origen), `session` (1: hash débil para sessionID), `body-parser` (2: datos de usuario en logs sin sanitizar). | `express`: cookies viajan en texto plano si la conexión no es HTTPS; la contraseña se pasa a `console.log()` sin cifrar. `cors`: refleja cualquier origen enviado, sin validación. `session`: hash débil (SHA1/MD5) rompible por fuerza bruta. `body-parser`: concatena datos del body al log sin escapar ni validar. | `express-codeql.json` (cookies sin Secure + password en logs), `cors-codeql.json` (CORS permisivo), `session-codeql.json` (crypto débil), `body-parser-codeql.json` (log injection), cada una con regla, archivo y línea. | Agregar `Secure` y `HttpOnly` a cookies. Eliminar `console.log(password)`. Restringir CORS a orígenes específicos. Reemplazar crypto débil por SHA-256. Sanitizar entradas en logs. |

*Tabla 6. Hallazgos de malas prácticas de configuración.*

---

## 5. Priorización de vulnerabilidades

La priorización combina **riesgo, probabilidad e impacto** de cada grupo:

| ID | Vulnerabilidad | Riesgo | Probabilidad | Impacto |
|---|---|---|---|---|
| V01 | Dependencias vulnerables | Medio | Alta | Medio |
| V02 | Code smells de seguridad | **Alto** | Alta | Alto |
| V03 | Secretos expuestos | **Alto** | Baja | Alto |
| V04 | Malas prácticas de configuración | **Alto** | Alta | Alto |
| V05 | Malas prácticas en pipelines | Bajo | Baja | Medio |

*Tabla 7. Categorización de grupos de riesgo.*

**Orden de atención propuesto:**

1. **V04 (malas prácticas de configuración)** y **V02 (code smells XSS)** — riesgo Alto con probabilidad Alta. Afectan código y, en el caso del XSS de `expressjs.com`, superficie pública en producción. Se atienden primero.
2. **V03 (secretos expuestos)** — riesgo e impacto Alto, pero probabilidad Baja (la mayoría son fixtures de prueba ya verificados). La API key de Algolia es la excepción de acción inmediata por ser real y reutilizable.
3. **V01 (dependencias vulnerables)** — riesgo Medio; hay fixes disponibles, se resuelve con actualización.
4. **V05 (pipelines)** — riesgo Bajo; se gestiona con auditoría periódica.

---

## 6. Acciones propuestas (mitigaciones)

Cada mitigación se identifica con un ID (M01–M15), su vulnerabilidad asociada y su naturaleza (correctiva o preventiva).

### Dependencias vulnerables (V01)

| ID | Descripción | Naturaleza | Impacto esperado |
|---|---|---|---|
| M01 | Actualización de Vite | Correctiva | Vite → 7.3.2, soluciona 3 vulnerabilidades incluyendo "arbitrary file read" (CVSS 8.2) |
| M02 | Actualización de Picomatch, defu, devalue | Correctiva | Soluciona ReDoS, prototype pollution y DoS |
| M03 | Configuración de Dependabot | Preventiva | Reporte semanal del estado de las dependencias de los repositorios |

### Code smells de seguridad (V02)

| ID | Descripción | Naturaleza | Impacto esperado |
|---|---|---|---|
| M04 | Corrección de XSS | Correctiva | Reemplazar código sensible en `SidebarVersionManager.ts` y `orama-documents.mjs`, mitigando XSS |
| M05 | Auditoría de pruebas XSS | Preventiva | Las alertas en tests se revisan en ceremonias de código para que no pasen a producción |
| M06 | Reglas de linting contra XSS | Preventiva | `eslint-plugin-security` / `no-unsafe-innerHTML` previenen reintroducción |

### Secretos expuestos (V03)

| ID | Descripción | Naturaleza | Impacto esperado |
|---|---|---|---|
| M07 | Parametrización de API key con secretos del repositorio | Preventiva | La API key deja de estar expuesta como valor plano |
| M08 | Eliminación de secretos del repositorio | Correctiva | Los secretos ya no son visibles en archivos ni commits |
| M09 | Generación de claves dinámicas en testing | Correctiva | Las claves de prueba no quedan expuestas en el repositorio |
| M10 | Pipeline de verificación de secretos | Preventiva | Si un secreto se expone en una ceremonia de integración, se alerta y cancela de inmediato |

### Malas prácticas de configuración (V04)

| ID | Descripción | Naturaleza | Impacto esperado |
|---|---|---|---|
| M11 | Restringir CORS | Correctiva | En `cors/lib/index.js` se cambia de origen permisivo a lista blanca de dominios |
| M12 | Migración a algoritmo de cifrado más seguro | Correctiva | Se reemplaza algoritmo débil por SHA-256 o mejor en `session/index.js:625` |
| M13 | Secure flag en cookies | Correctiva | Se añade `{ secure: true, httpOnly: true }` a las cookies en los ejemplos de `express` |
| M14 | Logging enmascarado | Preventiva | Los logs con claves y PII se enmascaran desde el lado del servidor |

### Malas prácticas en pipelines (V05)

| ID | Descripción | Naturaleza | Impacto esperado |
|---|---|---|---|
| M15 | Auditoría de pipelines | Correctiva | En cada ciclo iterativo se revisan las pipelines, indicando vulnerabilidades incorporadas por iteración |

Las medidas **preventivas** (M03, M05, M06, M07, M10, M14) y la auditoría continua (M15) constituyen la propuesta de seguridad permanente: cada versión vuelve a analizarse y cada excepción (falsos positivos, fixtures) vuelve a revisarse.

---

## 7. Evidencia utilizada

- `data/repos.json` — inventario de los 10 repositorios analizados.
- `data/results/*-sbom.json` — SBOMs generados con Syft.
- `data/results/*-grype.json` y `*-grype-raw.json` — vulnerabilidades de dependencias (ID, severidad, CVSS, fix version).
- `data/results/*-codeql.json` y `*_temp.sarif` — hallazgos de código con ruta, línea y regla.
- `data/results/*-gitleaks.json` — secretos detectados con ubicación y commit de origen.
- `scripts/` — automatización: `generate_sboms.py`, `generate_grype.py`, `generate_codeql.py`, `generate_gitleaks.py`.
- `evidence/notebooks/` — notebooks de análisis (SBOM, secretos, vulns de código y dependencias, análisis de componentes).
- `evidence/capturas/` — capturas del proceso y gráfico de hallazgos por repositorio.
- `evidence/reportes/Análisis ExpressJS.pptx.pdf` — presentación con el análisis consolidado.

---

## 8. Conclusiones

En relación a las vulnerabilidades conocidas, sus riesgos y sus mitigaciones:

- Se opta por **priorizar las mitigaciones correctivas** ante todo, enfatizando los esfuerzos en los **code smells de seguridad (V02)** y en las **malas prácticas de configuración (V04)**, por ser los grupos de riesgo Alto con mayor probabilidad y exposición en producción.
- Los secretos (V03) se atienden de inmediato solo donde son reales (API key de Algolia); los fixtures de prueba se documentan como falsos positivos controlados y se reemplazan por generación dinámica.
- Las **mitigaciones preventivas** son cruciales frente a futuros incidentes: permiten ahorrar en potenciales costos correctivos y mantenerse en línea con estándares de seguridad de la industria.

La propuesta combina corrección inmediata, validación de evidencia, prevención continua y mejora permanente. No asume que una corrección cierre el problema para siempre; asume que el sistema cambia y que el análisis debe repetirse para detectar riesgos nuevos antes de publicar nuevas versiones, reduciendo así el riesgo del sistema analizado.

---

## Apéndice: reproducir el análisis

Este repositorio incluye un Dev Container con Python, uv, Jupyter, Syft, Grype, CodeQL y Node.js.

```bash
# Preparar repositorios de ejemplo
uv run python scripts/add_submodules.py

# Ejecutar los análisis
uv run python scripts/generate_sboms.py
uv run python scripts/generate_codeql.py
uv run python scripts/generate_grype.py
uv run python scripts/generate_gitleaks.py
```

Los resultados se guardan en `data/results/`.

# Seguridad preventiva y gobierno de hallazgos

Este documento complementa el informe principal en [`README.md`](README.md) y la presentacion en [`PRESENTACION.md`](PRESENTACION.md). Su foco no es describir hallazgos pasados, sino prevenir que vulnerabilidades nuevas lleguen a versiones productivas.

## Directriz de mejora continua

La seguridad debe tratarse como un ciclo continuo, no como una correccion puntual. Aunque una version cierre todos los hallazgos conocidos, pueden aparecer riesgos nuevos por cambios de codigo, nuevas dependencias, nuevas CVE/GHSA, cambios en pipelines, nuevas tecnicas de ataque o falsos negativos de herramientas.

Por eso, estos analisis deben ejecutarse siempre:

- antes de cada version productiva
- despues de cambios relevantes en dependencias, CI/CD, autenticacion, sesiones, cookies, CORS, subida de archivos o parsing de entrada
- de forma periodica aunque no haya cambios grandes
- cuando las bases de datos de vulnerabilidades se actualicen
- cuando aparezcan nuevos criterios de revision humana o nueva evidencia externa

No existe una forma completamente deterministica ni inmediata de saber todo el riesgo del sistema. La decision correcta es mantener monitoreo, reevaluacion, documentacion y aprendizaje constante.

## 1. Pipeline preventiva propuesta

La propuesta es ejecutar una pipeline de seguridad en cada version del codigo antes de produccion:

- en cada pull request
- en cada merge a la rama principal
- en cada tag o release candidate
- antes de publicar artefactos o desplegar el sitio/documentacion

Controles minimos de la pipeline:

| Control | Herramienta sugerida | Objetivo | Criterio de bloqueo |
| --- | --- | --- | --- |
| SBOM | Syft | Conocer componentes reales del proyecto. | Falla si no se puede generar inventario. |
| Dependencias vulnerables | Grype | Detectar CVE/GHSA nuevos contra el SBOM. | Bloquear critical/high nuevos sin excepcion aprobada. |
| Analisis de codigo | CodeQL | Detectar patrones inseguros en codigo fuente. | Bloquear alertas nuevas de seguridad en codigo ejecutable. |
| Secretos | Gitleaks | Detectar secretos reales o fixtures sensibles versionados. | Bloquear secretos nuevos salvo fixtures documentados. |
| Diferencial contra baseline | Comparacion de reportes | Separar deuda conocida de riesgo nuevo. | Bloquear regresiones nuevas no justificadas. |

La pipeline debe distinguir entre deuda historica y vulnerabilidades nuevas. Para eso se recomienda mantener un baseline versionado de hallazgos aceptados y comparar cada ejecucion contra ese baseline.

## 2. Documentacion asociada requerida

Ademas de los reportes automaticos, deben mantenerse documentos de decision humana:

### Registro de falsos positivos

Cada falso positivo debe documentarse con:

- identificador del hallazgo
- archivo y linea afectada
- herramienta que lo detecto
- motivo de descarte
- evidencia usada para descartarlo
- responsable de la decision
- fecha de revision
- fecha de expiracion o proxima revision

Ejemplo esperado:

| Hallazgo | Ubicacion | Motivo | Responsable | Revalidacion |
| --- | --- | --- | --- | --- |
| Clave privada en fixture | `test/fixtures/server.key` | Fixture sintetico usado solo en tests locales. | Equipo de seguridad/desarrollo | Cada release o cambio en tests. |

### Lista de ignorados permitidos

No se deben ignorar codigos o rutas de forma global sin justificacion. Una regla de ignore debe indicar:

- regla o codigo ignorado
- alcance exacto: archivo, carpeta o prueba
- justificacion
- riesgo aceptado
- responsable
- fecha de expiracion

Ejemplo:

| Regla ignorada | Alcance | Justificacion | Expira |
| --- | --- | --- | --- |
| `private-key` de Gitleaks | `test/fixtures/server.key` | Fixture publico, no usado en produccion. | 90 dias |

### Criterios de revision humana continua

Hay casos donde la herramienta no decide sola. Debe revisar una persona cuando:

- aparece un secreto nuevo
- una dependencia vulnerable toca una superficie publica
- un hallazgo esta en codigo ejecutable y no solo en tests/ejemplos
- se pide ignorar una alerta de seguridad
- cambia la configuracion de CI/CD o despliegue
- se agrega una dependencia nueva critica para runtime
- el hallazgo afecta autenticacion, sesiones, cookies, CORS, carga de archivos o parsing de entrada

## 3. Politica de decision

La decision recomendada es:

1. Bloquear lo nuevo y critico.
2. Validar manualmente lo ambiguo.
3. Documentar falsos positivos con expiracion.
4. No aceptar ignores permanentes sin dueño.
5. Re-ejecutar herramientas despues de cada correccion.
6. Reabrir analisis cuando cambie el contexto tecnico o aparezca nueva evidencia.
7. Revisar periodicamente el baseline para evitar que la deuda aceptada se vuelva invisible.

## 4. Ciclo de mejora continua

Cada iteracion de seguridad debe seguir este ciclo:

1. Analizar: ejecutar pipeline, revisar reportes y comparar contra baseline.
2. Decidir: clasificar hallazgos como vulnerabilidad real, deuda aceptada, falso positivo o riesgo a investigar.
3. Actuar: corregir, mitigar, documentar excepciones o escalar a revision humana.
4. Aprender: actualizar criterios, reglas de ignore, documentacion y controles.
5. Repetir: ejecutar nuevamente en la siguiente version o cuando cambie el contexto.

La mejora continua evita que el analisis sea una foto estatica. El sistema cambia, las dependencias cambian y el conocimiento sobre amenazas tambien cambia.

## 5. Ideas adicionales incorporables

- Dependabot o Renovate para proponer actualizaciones de dependencias.
- Branch protection para exigir que pasen checks de seguridad antes de merge.
- Scorecards u OpenSSF para evaluar salud del proyecto y practicas de supply chain.
- Firmado de releases y tags para aumentar trazabilidad.
- Revisiones periodicas de permisos de CI/CD y tokens.
- Politica de minimo privilegio para secretos usados por pipelines.
- Deteccion de cambios sospechosos en workflows de GitHub Actions.
- Revision manual obligatoria cuando cambien archivos de seguridad, CI/CD o dependencias.
- Métricas de tendencia: hallazgos nuevos, hallazgos cerrados, tiempo medio de remediacion y excepciones vencidas.
- Reuniones breves de revision post-release para ver que hallazgos aparecieron tarde y ajustar controles.
- Calendario de revalidacion de falsos positivos y excepciones aceptadas.
- Monitoreo de advisories externos de GitHub, NPM, OSV y fuentes del ecosistema Node.js.

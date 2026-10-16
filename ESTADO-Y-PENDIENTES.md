# Entrega de avance · ARCOP Open y Gen-Auditor

Fecha: 16 de octubre de 2026. **Entrega de desarrollo ampliada, no suite completa aceptada para producción.**

## Son dos productos separados

- `packages/arcop-open/`: componente open source MIT con servicio HTTP, panel embebible, contrato de integración independiente del lenguaje y flujo ARCOP. No necesita PHP ni el paquete municipal para ejecutarse.
- `apps/gen-auditor/`: aplicación de gobernanza y ciberseguridad con React/Tailwind, API Node y esquema PostgreSQL/Supabase. Supervisa privacidad y seguridad; no reemplaza el paquete ARCOP.
- El paquete Composer histórico en la raíz conserva su funcionamiento y licencia. `laravel-muni-shared` figura como proprietary y no se ha relicenciado ni copiado dentro de los productos nuevos.

## Implementado en el código

### Gen-Auditor
- Interfaz responsive con sidebar, dashboard, privacidad, clientes/dominios, hallazgos, bitácora e integración ARCOP; demostración expresamente ficticia.
- Autenticación JWT asimétrica con JWKS Supabase; comprobación MFA configurable, RBAC y contexto de tenant por transacción.
- SQL de tenants, miembros, clientes, dominios, consentimientos, solicitudes proyectadas, evaluaciones, incidentes, riesgos, controles, escaneos, hallazgos, auditoría e informes.
- RLS, relaciones compuestas por tenant, bitácora de solo anexado para rol runtime y cadena SHA-256 con verificación.
- Cifrado AES-GCM de identidad/IP/user agent y referencia HMAC del titular.
- Verificación DNS TXT y comprobación HTTPS acotada con protección SSRF, DNS fijado y sin redirecciones.
- Autorizaciones de escaneo y worker opcional Nmap de alcance TCP 80/443, bloqueado por defecto. No se ejecutaron escaneos externos ni se desplegó el worker.
- PDF ejecutivo y manifiesto con firma técnica Ed25519; no firma electrónica avanzada acreditada.
- Separación de plazos legales de incidentes y SLA internos; controles de evidencia, revisión y métricas sin inventar cumplimiento.

### ARCOP Open
- Servicio independiente con emisor OIDC/JWKS configurable, RLS y roles recepción/resolución/auditoría.
- Recepción con Idempotency-Key y cifrado de datos personales.
- Transiciones para verificar identidad, aprobar/rechazar y acreditar ejecución externa, con separación entre receptor y resolutor.
- Resoluciones bloqueadas hasta revisar y habilitar el perfil legal correspondiente.
- Evidencia encadenada por expediente; hashes de documentos, sin rutas de borrado controladas por el cliente.
- Panel HTML/CSS/JS embebible; credenciales solo en memoria mediante postMessage desde origen configurado. No tokens en URL/localStorage.
- Cliente JavaScript HTTP y helper de integración iframe. El mismo contrato se consume desde otros lenguajes.

## Validación realizada y límites

- Compilación React/Vite inicial correcta; sintaxis y primeras pruebas de servicios.
- Batería ampliada: 10 pruebas de dominio/API/PostgreSQL correctas, incluyendo el servicio ARCOP independiente; 2 pruebas adicionales de workflow/SDK ARCOP correctas. Ver VALIDACION.md para la ejecución final.
- Comprobar las pruebas y build con los comandos incluidos antes de aceptar esta copia en tu entorno.
- No se ejecutaron las pruebas PHP/Composer: este entorno no dispone de PHP.
- No hay despliegue real, proyecto Supabase configurado, usuarios, CA, SMTP, secretos reales ni pruebas contra sistemas externos.
- Se ejecutaron comprobaciones de navegador: dashboard/privacidad, filtro de clientes y navegación móvil sin overflow; ARCOP embebido entre dos orígenes, recepción autenticada y ausencia de localStorage. No sustituyen auditoría de accesibilidad ni aceptación real de OIDC/Supabase.

## Qué completar, en orden

1. Ejecutar de nuevo `cd apps/gen-auditor && npm ci && npm test && npm run build` y `cd packages/arcop-open && npm ci && npm test`.
2. Probar ARCOP end-to-end contra PostgreSQL: roles, RLS, idempotencia, transiciones, firma/hashes de evidencia y separación de personas. Completar los tests de integración del panel embebido y rechazo de orígenes.
3. Validar visualmente desktop/móvil, navegación por teclado, formularios, gestión del foco, errores y estados vacíos. Revisar CSP, autenticación, renovación y cierre de sesión.
4. OpenAPI y ejemplos Python/PHP/cURL/JavaScript incluidos. Validar ejemplos en cada entorno y ampliar contratos cuando se añadan funciones. No se ha publicado en npm ni Packagist.
5. Documentación de arquitectura, amenazas y operación incluida. Completar políticas legales versionadas, automatización de backups y recuperación ensayada.
6. Dockerfile/Compose incluidos, no ejecutados aquí. Construir y probar imágenes, generar secretos, instalar CA y crear roles mínimos. Nunca usar postgres/service_role ni versionar secretos.
7. Crear usuarios del proveedor OIDC y membresías por administración controlada. Verificar MFA e incorporación. El panel no crea tenants ni roles automáticamente desde el navegador.
8. Revisar perfiles legales con responsable competente: aplicabilidad Ley 21.663, Ley 19.628 y transición Ley 21.719 (vigente desde 01-12-2026), plazos y conservación. No tratar 48 h ni 12 meses como obligaciones universales.
9. Implementar y aceptar el adaptador de ejecución ARCOP en cada sistema anfitrión: acceso, rectificación, bloqueo/supresión, oposición y portabilidad. Un estado en el panel no cambia por sí solo datos o tratamientos externos.
10. Conectar Gen-Auditor con ARCOP mediante proyecciones/webhooks firmados y deduplicados. La recepción en Gen-Auditor está bloqueada: corresponde al producto independiente. El conector de sincronización todavía no está implementado.
11. Para escaneo activo: crear identidad y rol de worker, instalar Nmap en contenedor aislado, validar licencias de herramientas, egress y ventana de autorización. Ejecutar solo en alcance expresamente autorizado. Nmap TCP 80/443 es inventario acotado, no pentesting completo.
12. Ampliar ciberseguridad: inventario de activos, campañas de pentesting, importación/normalización de Nuclei/ZAP/SARIF/Trivy, SBOM, IAM/cloud, gestión de evidencias y remediación/retest. Estos conectores no están implementados; no anunciar cobertura completa automática.
13. Persistir evidencia documental en repositorio privado con retención/holds; completar anclajes externos de auditoría y recuperación ensayada. El propietario de una BD puede reescribir la infraestructura: una cadena de hashes local no es inmutabilidad absoluta.
14. Integrar reportes oficiales solo mediante canales autorizados; actualmente se registran evidencias de reportes, no se envían incidentes a ANCI.
15. Ejecutar auditoría de dependencias, pruebas de carga, análisis de seguridad, SQL en Supabase real y recuperación completa antes de producción.
16. Revisar la rama/PR de desarrollo y aceptar pruebas antes de fusionar. No se despliega ni fusiona automáticamente. Consultar el enlace de entrega para el estado de publicación.

## Arranque del desarrollo

Gen-Auditor: `npm ci`, `npm run dev` para interfaz. La demostración está en `http://127.0.0.1:5173/?demo=1`. No necesita backend para mostrar datos ficticios; las operaciones reales sí requieren configuración de API/BD.

ARCOP: `npm ci`, `node init.mjs`, completar .env, ejecutar SQL/schema.sql como administrador en una base de ensayo y provisionar miembros; `npm start` inicia servicio y panel. En Docker las variables van por entorno y el comando deberá ejecutar directamente `node src/server.js`.

Cada producto tiene .env.example; no se incluyen credenciales reales. No apuntar las migraciones a bases productivas sin backup y revisión.

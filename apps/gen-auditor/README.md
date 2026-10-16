# Gen-Auditor · Gobernanza y ciberseguridad

Aplicación independiente del paquete ARCOP: React/Tailwind, API Node, PostgreSQL con RLS y autenticación Supabase. Código nuevo bajo MIT; no modifica la licencia del paquete Composer histórico.

**Estado: implementación inicial verificable, no suite completa aceptada para producción.** Ver [arquitectura y cobertura](docs/ARQUITECTURA.md), [seguridad](docs/SEGURIDAD.md), [operación](docs/OPERACION.md) y el [estado general](../../ESTADO-Y-PENDIENTES.md).

## Desarrollo

Node 22.12+ (se comprobó con 24.19):

```sh
npm ci
npm test
npm run build
npm run dev
```

Interfaz: `http://127.0.0.1:5173/?demo=1`. La demostración usa fixtures explícitos, no ejecuta escaneos ni genera firmas falsas. Para API real, ejecutar `node scripts/init.mjs`, editar .env, instalar CA y revisar los SQL como administrador. En desarrollo local ajustar las rutas de CA/clave del .env a archivos existentes y APP_ORIGIN al origen del frontend. `npm run api` inicia la API; Vite redirige /api al puerto 3000.

## Qué funciona en el código

- Clientes/dominios y desafío DNS, chequeo HTTPS acotado, hallazgos y tratamiento.
- Consentimientos cifrados, retiro registrado, EIPD en borrador y planes de anonimización propuestos.
- Riesgos, controles con revisión independiente, incidentes con registro manual de etapas.
- Auditoría encadenada/verificación; PDF + manifiesto Ed25519.
- Worker opcional Nmap TCP 80/443 sujeto a autorización y alcance. Desactivado por defecto.
- Buzón ARCOP de **supervisión**: no recibe ni resuelve solicitudes. El servicio separado es [ARCOP Open](../../packages/arcop-open/README.md). La sincronización entre ambos es pendiente.

## Qué no debe anunciarse como terminado

Pentesting integral, conectores Nuclei/ZAP/SARIF/Trivy/SIEM/cloud, SBOM, envío automático ANCI, sincronización ARCOP, ejecución de anonimización/supresión externa, firma avanzada acreditada, anclaje WORM y recuperación de producción. La especificación define estas extensiones y sus criterios de aceptación.

## Esquema/API

SQL en `sql/`, servicio en `server/`, UI en `web/`, pruebas en `tests/`. `sql/002_runtime_role.sql` crea el rol `gen_auditor_api` sin privilegios administrativos; contraseña fuera del repo. Ejecutar las migraciones exclusivamente en una base de ensayo respaldada. No hay migración automática sobre los datos ARCOP existentes.

Las dependencias npm están fijadas en package-lock.json. Nunca publicar .env, CA privadas, claves de cifrado o firma. La clave pública de Supabase sí se entrega al navegador; service_role nunca.

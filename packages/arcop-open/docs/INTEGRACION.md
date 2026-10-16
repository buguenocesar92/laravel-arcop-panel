# Integración independiente del lenguaje

## API de referencia

Requiere access token firmado por el emisor configurado, audience correcta, membresía activa y `X-Tenant-ID`. No enviar id tokens como access tokens ni confiar en un JWT decodificado sin verificar. MFA requiere `aal=aal2` en esta implementación: si el proveedor usa otra semántica, adaptar y probar el mapeo antes de habilitarlo; no desactivar MFA silenciosamente.

| Método | Recurso | Propósito |
| --- | --- | --- |
| GET | /v1/session | Rol y tenant autenticados |
| GET | /v1/requests | Buzón del tenant, máximo 100, sin PII descifrada |
| POST | /v1/requests | Recepción; exige Idempotency-Key UUID |
| GET | /v1/requests/{id}/events | Evidencia/encadenamiento e integridad calculada |
| POST | /v1/requests/{id}/transitions | Transición validada y auditada |

La retención/paginación avanzada, búsqueda protegida, lectura privilegiada de documentos y calendario jurídico son pendientes. El host conserva la relación entre su titular local y la referencia externa; no usar el HMAC como identificación pública.

## cURL

Guardar token en un entorno protegido. No compartir historial ni trazas que contengan Authorization.

```sh
curl --fail-with-body https://arcop.tudominio.cl/v1/requests \
  -H "Authorization: Bearer $ARCOP_ACCESS_TOKEN" \
  -H "X-Tenant-ID: $ARCOP_TENANT_ID" \
  -H "Idempotency-Key: $ARCOP_REQUEST_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary @solicitud.json
```

```json
{"product":"Mi sistema","identity":"identificador del titular","right_type":"access","description":"Solicitud recibida para verificar y tramitar.","legal_profile":"review_required"}
```

## Python (servidor)

```python
import json, os, uuid, urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
body = {"product": "Mi sistema", "identity": "titular-local",
        "right_type": "access", "description": "Solicitud a verificar."}
request = urllib.request.Request(
    "https://arcop.tudominio.cl/v1/requests",
    data=json.dumps(body).encode(),
    headers={"Authorization": "Bearer " + os.environ["ARCOP_ACCESS_TOKEN"],
             "X-Tenant-ID": os.environ["ARCOP_TENANT_ID"],
             "Idempotency-Key": str(uuid.uuid4()),
             "Content-Type": "application/json"})
with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
    result = json.load(response)
```

Conservar la misma Idempotency-Key para reintentar **la misma** operación; no generar otra si un timeout impide saber si se recibió. El ejemplo genera una nueva solo al crear la operación inicial.

## PHP (servidor, sin dependencia Laravel)

```php
<?php
$ch = curl_init('https://arcop.tudominio.cl/v1/requests');
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer '.getenv('ARCOP_ACCESS_TOKEN'),
        'X-Tenant-ID: '.getenv('ARCOP_TENANT_ID'),
        'Idempotency-Key: '.getenv('ARCOP_REQUEST_KEY'),
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode([
        'product' => 'Mi sistema', 'identity' => 'titular-local',
        'right_type' => 'access', 'description' => 'Solicitud a verificar.',
    ], JSON_THROW_ON_ERROR),
]);
$result = curl_exec($ch);
if ($result === false || curl_getinfo($ch, CURLINFO_HTTP_CODE) >= 400) {
    throw new RuntimeException('ARCOP rechazó o no completó la operación');
}
curl_close($ch);
```

Java, .NET, Go y otros lenguajes usan exactamente el mismo contrato HTTPS. Los ejemplos Python/PHP son de integración y no se ejecutaron en este entorno; el SDK JavaScript y el contrato HTTP sí tienen pruebas.

## Panel embebido

1. El operador permite `https://mi-sistema.cl` en EMBED_ALLOWED_ORIGINS.
2. El anfitrión crea iframe hacia el origen ARCOP HTTPS. Añadir título accesible y Referrer-Policy compatible con enviar origen al servicio; sin referrer el handshake no se inicia.
3. Registrar el helper antes de asignar src o antes de que cargue el frame, para no perder `arcop.ready`.
4. El host obtiene un access token del issuer/audience confiables. Si usa otra identidad, necesita un intercambio de tokens de servidor diseñado para ese fin; no crear JWT desde el navegador.
5. El frame acepta credenciales únicamente si event.source es parent y event.origin está en la lista exacta. El host también valida origen y contentWindow. Se almacenan solo en memoria.

```javascript
import { connectArcopFrame } from './client.mjs';
const frame = document.createElement('iframe');
frame.title = 'Gestión de derechos de datos';
document.querySelector('#arcop').append(frame);
const disconnect = connectArcopFrame(frame, {
  serviceOrigin: 'https://arcop.tudominio.cl',
  tenant: tenantId,
  getToken: () => identityProvider.getAccessToken(),
});
frame.src = 'https://arcop.tudominio.cl/';
```

No tokens en URL, fragmentos, HTML persistido o atributos data-*. No usar targetOrigin='*'. La renovación de credenciales y manejo de expiración en el host deben completarse para sesiones largas. No hay CORS abierto para que cualquier web consuma la API: usar integración server-to-server, BFF o el frame del mismo origen del servicio.

## Ejecución y evidencia

Los documentos de identidad, fundamentos y comprobantes originales permanecen en el repositorio privado del responsable. ARCOP guarda hashes/referencias necesarias. Un hash no prueba identidad ni autorización por sí solo. No aceptar rutas arbitrarias de archivo para ejecutar borrados en el host.

Aprobar → action_pending. Un adaptador del host valida alcance y aplica acceso/corrección/bloqueo/cese/exportación según decisión. Después devuelve comprobante y su SHA-256 para complete. No completar antes de ejecutar. Si una obligación de conservación impide suprimir, resolver con fundamento mediante política validada; no añadir una excepción informal en la UI.

## Pendientes de producción

- Políticas jurídicas versionadas y calendarios de plazos/suspensión.
- Almacenamiento de evidencia, retención, legal hold y acceso privilegiado auditado.
- Adaptadores por sistema anfitrión y pruebas de efectos reales.
- Webhooks firmados/outbox con reintentos, deduplicación y protección SSRF; no existe entrega automática ahora.
- Renovación/revocación de sesiones, mapeo MFA de proveedores distintos y alta controlada de miembros.
- Notificaciones, portal público con identidad y límites contra enumeración, paginación, exportación de expediente y anclaje externo de hashes.
- Auditoría de accesibilidad y seguridad independiente, TLS/BD reales y recuperación ensayada.

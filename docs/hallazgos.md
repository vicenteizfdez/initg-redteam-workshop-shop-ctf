# Hallazgos y remediaciones

Contexto completo de cada hallazgo en el [informe de metodología](./informe.md).

## Tabla de hallazgos

| ID | Título | Severidad | Componente |
|---|---|---|---|
| F1 | Fuga de información (stack trace / ruta de despliegue) ante petición HTTP malformada | Baja | App web |
| F2 | Ausencia de protección CSRF en formularios de escritura | Media | App Sinatra |
| F3 | **Command Injection + SSTI no autenticados en `POST /coupon`** | **Crítica** | App Sinatra — `/coupon` |
| F4 | Control de acceso roto: lógica de login/admin bypasseable ejecutando código Ruby directamente sobre los modelos | **Alta** | App Sinatra |
| F5 | **Binario SUID con `system()` vulnerable a secuestro de `PATH`** | **Crítica** | Binario SUID no estándar |
| F6 | Credenciales de servicio interno (Redis) transmitidas en texto plano y extraíbles por interceptación de tráfico local | **Alta** | `payments.internal:6379` |
| F7 | **Command Injection no autenticado en worker de procesamiento de transacciones**, RCE como usuario con `sudo` | **Crítica** | `payments.internal` |

## Detalle y remediación por hallazgo

### F1 — Fuga de información en errores

- **Causa raíz:** excepciones no controladas en producción exponen *stack trace* y rutas del sistema.
- **Remediación:** capturar excepciones genéricas y desactivar `show_exceptions` en producción.

### F2 — Ausencia de protección CSRF

- **Causa raíz:** formularios de escritura sin token CSRF.
- **Remediación:** añadir protección CSRF estándar (p. ej. `rack-protection` o tokens explícitos) a todos los formularios de escritura.

### F3 — Command Injection + SSTI en `/coupon`

- **Vector:** parámetro `email` del formulario de solicitud de cupón, sin autenticación.
- **Causa raíz:** interpolación directa de entrada de usuario dentro de `system()` y dentro de una plantilla ERB evaluada dos veces.
- **Impacto:** ejecución de código arbitrario como el usuario de la aplicación.
- **Remediación:** nunca interpolar entrada de usuario en `system()`/backticks; nunca volver a evaluar una cadena ya interpolada como plantilla (`ERB.new(...).result`). Sanear/escapar siempre, o eliminar el doble renderizado.
- **Detección:** ver cabecera de [`scripts/rce_via_ssti.sh`](../scripts/rce_via_ssti.sh) para indicadores de WAF/IDS y logging.

### F4 — Control de acceso roto (bypass de login)

- **Causa raíz:** helpers de autenticación deshabilitados "a medias" en código que sigue siendo invocable (los modelos y la gestión de sesión seguían activos aunque la ruta HTTP de login estuviera apagada).
- **Impacto:** acceso administrativo sin pasar por ningún control de autenticación.
- **Remediación:** no dejar lógica de negocio sensible invocable si la ruta HTTP que la protege está desactivada; proteger con *feature flags* reales a nivel de todas las rutas que dependen de sesión, no solo en el controlador de login.

### F5 — PATH hijacking en binario SUID

- **Vector:** binario SUID root que invoca `system("systemctl status ...")` sin ruta absoluta y sin sanitizar `PATH`.
- **Causa raíz:** confianza implícita en el entorno del proceso que invoca el binario SUID.
- **Impacto:** escalada completa de usuario de aplicación a root.
- **Remediación:** fijar `PATH` explícitamente (o usar rutas absolutas) en cualquier binario con bit SUID antes de invocar `system()`/`execve()`; evitar SUID salvo estrictamente necesario, y auditar binarios no estándar en directorios de usuario.
- **Detección:** ver cabecera de [`scripts/privesc_path_hijack.sh`](../scripts/privesc_path_hijack.sh) para indicadores de EDR/auditd.

### F6 — Credenciales en texto plano (Redis)

- **Causa raíz:** protocolo Redis sin TLS; credencial ofuscada en el binario pero visible en tránsito.
- **Impacto:** acceso no autorizado a un servicio interno crítico mediante captura pasiva de tráfico.
- **Remediación:** no transmitir credenciales de servicios internos en texto plano, ni siquiera en redes "internas"; usar TLS para Redis (`stunnel`/`redis-cli --tls`) y rotar credenciales si se filtran.

### F7 — RCE en sistema de pagos

- **Vector:** campo `notes` de las transacciones consumidas desde la cola Redis `transactions`.
- **Causa raíz:** mismo patrón que F3 — construcción insegura de un comando de shell a partir de datos de un mensaje de cola no autenticado/no validado.
- **Impacto:** ejecución de comandos en el sistema financiero real, como usuario con privilegios de `sudo` — máximo impacto posible dentro del alcance del reto.
- **Remediación:** validar y tipar estrictamente los mensajes consumidos de colas internas; tratar cualquier dato proveniente de una cola como entrada no confiable, igual que una petición HTTP externa.

## Flags capturadas

Dos flags del formato `FLAG{...}` se capturaron como evidencia de explotación (F3 y F5). Se omiten completas en este repositorio público: la infraestructura del workshop se reutiliza entre cohortes de estudiantes, y publicar la solución completa permitiría a futuros participantes copiarla en vez de resolver el reto.

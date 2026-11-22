# Informe técnico — metodología por fases

> Los nombres de hosts, rutas y algunos detalles se han generalizado respecto al entorno original del workshop (ver nota en el [README](../README.md)).

## Alcance y reglas de la prueba

- **Objetivo autorizado:** una tienda de e-commerce de laboratorio (`target.redacted`) y, por descubrimiento durante la prueba, un host interno de pagos (`payments.internal`, solo accesible desde la red del laboratorio).
- **Workstation de origen:** máquina provista por los organizadores del workshop.
- **Autorización:** ejercicio explícitamente diseñado y habilitado por los organizadores para practicar red teaming ofensivo con un objetivo financiero simulado.
- **Fuera de alcance:** cualquier sistema no perteneciente a la infraestructura del workshop.

---

## 1. Reconocimiento de red

```bash
nmap -Pn -sC -sV -p- -T4 target.redacted
```

Resultado: solo dos puertos expuestos.

| Puerto | Servicio |
|---|---|
| 22/tcp | OpenSSH |
| 8888/tcp | HTTPS — aplicación Ruby (Sinatra) bajo Puma, con certificado autofirmado |

Una sonda genérica de `nmap` contra el puerto 8888 disparó un **error 500 con stack trace completo**, filtrando el framework/versión exactos y la ruta absoluta de despliegue de la app en el servidor (hallazgo F1).

## 2. Reconocimiento de la aplicación web

La aplicación es una tienda ficticia con una característica de desarrollo dejada activa a propósito: **cada página expone su propio código fuente** (botón "Inspect Code"), lo que aceleró enormemente el análisis de la lógica de negocio sin necesidad de descompilar nada.

Enumeración de directorios reveló rutas no enlazadas desde el HTML:

```
/admin      → 302 a /login (protegida)
/cart       → 302 a /login (protegida)
/settings   → 302 a /login (protegida)
/coupon     → 200 OK, SIN protección de sesión
```

## 3. Explotación inicial — Command Injection + SSTI en `/coupon`

El código fuente del endpoint de solicitud de cupón (visible gracias a "Inspect Code") reveló un patrón de interpolación sin sanitizar:

```ruby
post '/coupon' do
  email = params[:email]
  system("bash -c \"echo User #{email} requested a coupon. >> /tmp/coupon_requests.log\"")
  @confirmation_message = t(:coupon_confirmation, email: email)
  erb :coupon
end
```

Dos vulnerabilidades coexistían en el mismo endpoint:

- **Command Injection**: `email` se interpola directamente dentro de `system()`.
- **SSTI por doble evaluación**: el mensaje de confirmación se construye con el `email` del usuario y luego se vuelve a evaluar como plantilla ERB (`ERB.new(mensaje).result(binding)`). La causa raíz no es ERB en sí, sino tratar un string con datos de usuario como si fuera código de plantilla de confianza.

**Por qué la SSTI es más grave que la Command Injection por sí sola:** la Command Injection solo permite ejecutar lo que cabe en una línea de shell. La SSTI permite ejecutar **Ruby arbitrario** dentro del proceso de la aplicación — no solo lanzar comandos (`%x(...)`), sino invocar directamente cualquier método, clase o modelo cargado en memoria. Esa diferencia es la que, más adelante, permitió crear un usuario y forjar una sesión sin pasar por el endpoint de login (ver F4): no hacía falta atacar el login, bastaba con llamar a los mismos métodos Ruby que el login habría llamado.

Comprobación de concepto (genérica, contra un laboratorio propio):

```bash
curl -sk -X POST https://target.redacted:8888/coupon \
  --data-urlencode 'email=<%= 7*7 %>'
# → si la respuesta refleja "49", el motor de plantillas está
#   evaluando Ruby real, no mostrando el texto tal cual.
```

A partir de ahí, `%x(comando)` dentro del mismo `<%= %>` ejecuta comandos de sistema con los privilegios del proceso de la aplicación (`uid=1001`, usuario propio de la app). El script [`scripts/rce_via_ssti.sh`](../scripts/rce_via_ssti.sh) automatiza esta técnica de forma genérica — ver su cabecera para el razonamiento completo y las mitigaciones.

🚩 Primera flag obtenida leyendo un fichero del directorio de la app, confirmando el punto de entrada (ver [hallazgos](./hallazgos.md#flags-capturadas)).

## 4. Bypass de autenticación (sin usar la vulnerabilidad de login)

El código de `/login` y `/register` estaba **intencionadamente deshabilitado** (lógica real comentada, siempre redirige con un error). Sin embargo, al tratarse de ejecución de **Ruby real** (no solo shell), se pudo:

1. Instanciar un usuario directamente con el método `User.create(...)` del modelo (que seguía siendo funcional; solo la *ruta HTTP* estaba apagada).
2. Escribir directamente en el objeto de sesión de la petición: `session[:user_id] = usuario.id`.
3. Leer la clave de acceso de administrador, también accesible como atributo de clase público, y calcular el token esperado por `/admin`.

Todo en una sola inyección, encadenando la misma SSTI del paso 3 con la lógica de negocio real de la app. Resultado: sesión autenticada forjada + acceso al panel `/admin`, sin pasar nunca por un formulario de login real (hallazgo F4).

## 5. Escalada de privilegios a root — PATH hijacking en binario SUID

Enumeración de binarios SUID:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Reveló un binario SUID de root **no estándar** (no perteneciente a ningún paquete del sistema). Su análisis (`strings` + comportamiento observado) mostró, en esencia:

```c
setuid(0);
system("systemctl status shop_app");   // llamada SIN ruta absoluta
```

**Razonamiento del hijack:** un binario SUID se ejecuta con el EUID del propietario (root), pero no reinicia automáticamente las variables de entorno del proceso que lo invoca — entre ellas, `PATH`. Si ese binario llama a otro programa por nombre (no por ruta absoluta), la resolución de ese nombre depende del `PATH` heredado del atacante. Bastaba con:

1. Anteponer un directorio propio y escribible al `PATH`.
2. Colocar en ese directorio un ejecutable con el mismo nombre que el programa invocado (`systemctl`), que copiara `/bin/bash` y le pusiera el bit SUID.
3. Ejecutar el binario SUID con ese `PATH` modificado.

El binario SUID, creyendo invocar `systemctl` real, ejecuta en su lugar el impostor — con privilegios de root. El script [`scripts/privesc_path_hijack.sh`](../scripts/privesc_path_hijack.sh) automatiza esta técnica de forma genérica, parametrizada por la ruta del binario SUID y el directorio de hijack — ver su cabecera para el razonamiento completo y las mitigaciones.

🚩 Segunda flag obtenida tras confirmar `euid=0` (ver [hallazgos](./hallazgos.md#flags-capturadas)).

## 6. Movimiento lateral — descubrimiento del sistema de pagos

Con shell de root en el target, `/etc/hosts` reveló un host interno **no visible desde el exterior ni desde la red del workstation**: `payments.internal`.

Escaneo interno (desde el propio target, que sí tiene ruta de red hacia ese host) encontró Redis (puerto 6379) **con autenticación activada**.

Búsqueda de binarios/artefactos relacionados reveló un binario compilado en C que usa `hiredis` para autenticarse contra Redis y ejecutar `LPUSH transactions <json>`, con la contraseña **ofuscada en el binario mediante XOR** (no en texto plano en disco).

En lugar de invertir el cifrado, se interceptó el tráfico de red real con `strace`, ya que el protocolo Redis viaja sin TLS:

```bash
strace -f -e trace=network,write -s 500 /opt/scripts/sync_payments payments.internal
```

La contraseña de Redis quedó expuesta en texto plano en el propio tráfico generado por la herramienta legítima del sistema (hallazgo F6). **Lección aplicable:** interceptar tráfico de red local es con frecuencia más rápido que intentar revertir ofuscación/cifrado aplicado a una credencial embebida en un binario.

## 7. RCE en el sistema de pagos vía inyección en cola de mensajes

Con la contraseña capturada, se conectó directamente a Redis (sin depender del binario original) y se empujaron transacciones propias a la cola `transactions`. Un worker en `payments.internal` consume esa cola y genera un "informe de transacción" reflejando el campo `notes` recibido sin sanitizarlo — el mismo patrón de inyección de comandos que en el punto de entrada original (F3), repetido en un servicio distinto.

Prueba de inyección (genérica):

```bash
redis-cli -h payments.internal -p 6379 -a '<REDACTED_PASSWORD>' --no-auth-warning \
  LPUSH transactions '{"user": "redacted", "action": "purchase", "item_id": 1, "notes": "test_$(id)_end"}'
```

El `id` se ejecutó **en el servidor de pagos**, confirmando RCE como el usuario `ubuntu`, miembro del grupo `sudo` (hallazgo F7 — crítico, máximo impacto dentro del alcance del reto).

**Por qué se repitió:** la misma clase de vulnerabilidad (construir un comando de shell interpolando datos no confiables) apareció en dos servicios distintos de la misma organización — la tienda y el worker de pagos —, lo que sugiere un patrón de código compartido o un mismo equipo de desarrollo detrás de ambos.

---

## Estado y próximos pasos al cierre del ejercicio

Al cierre de esta sesión de trabajo, la cadena de ataque estaba **confirmada hasta ejecución de comandos en `payments.internal`**, pero **sin confirmación verificada** de una shell interactiva estable de vuelta ni de la manipulación efectiva de un saldo/transacción real — el objetivo final ("Obtain Money") quedó **en progreso**, no completado, para no exagerar el resultado.

Próximos pasos planeados:

1. Diagnosticar por qué la conexión de reverse shell saliente desde `payments.internal` no llegaba al listener (¿firewall de salida restringido a puertos/destinos concretos?).
2. Con shell estable en `payments.internal`, localizar el almacén real de saldos/cuentas y entender el modelo de datos de "transacción" más allá del campo `notes`.
3. Diseñar una transacción legítima dentro del esquema esperado que efectivamente acredite fondos, en vez de depender de inyección de comandos para cada paso.

## Lecciones aprendidas

- Una función de "ver código fuente" dejada activa (por error o como ayuda didáctica) puede convertirse en el mejor vector de reconocimiento disponible para un atacante.
- La misma clase de vulnerabilidad puede repetirse en distintos servicios de una misma organización si comparten patrones de código o equipo.
- Interceptar tráfico de red local (`strace`) es con frecuencia más rápido que intentar revertir ofuscación/cifrado aplicado a una credencial embebida en un binario.
- Documentar la cadena completa en tiempo real (notas estructuradas por hallazgo) fue clave para no perder el hilo en una sesión larga con muchos hallazgos encadenados.

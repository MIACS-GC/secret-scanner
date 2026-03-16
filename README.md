# 🔍 M6T2 — Escáner de Secretos en Repositorios Git

Herramienta de detección de secretos (contraseñas, API keys, tokens, etc.) en código fuente, con integración mediante git hook `pre-commit` y soporte para falsos positivos.

---

## 📁 Estructura del proyecto

```
secret-scanner/
├── scanner.py          # Escáner principal
├── example_app.py      # Fichero de ejemplo con secretos (dado en el enunciado)
├── setup.sh            # Script de instalación automática
├── .git-hooks/
│   └── pre-commit      # Hook git que bloquea commits con secretos
└── README.md
```

---

## 🚀 Instalación

```bash
# 1. Clona o descarga el proyecto
cd secret-scanner

# 2. Ejecuta el script de configuración
bash setup.sh
```

El script inicializa el repositorio git y copia el hook `pre-commit` al lugar correcto.

---

## 🛠️ Uso del escáner

### Escanear todo el proyecto
```bash
python3 scanner.py
```

### Escanear una carpeta específica
```bash
python3 scanner.py --path src/
```

### Ver solo los ficheros en staging (antes de commit)
```bash
python3 scanner.py --staged
```

---

## ⚠️ Git Hook (pre-commit)

Una vez instalado con `setup.sh`, el hook se activa automáticamente al ejecutar `git commit`. Si detecta secretos, **bloquea el commit** y muestra los hallazgos.

```
🔍  [pre-commit] Ejecutando escáner de secretos...
❌  COMMIT BLOQUEADO: Se detectaron secretos en los ficheros.
```

Para saltarlo puntualmente (**no recomendado**):
```bash
git commit --no-verify
```

---

## ✅ Gestión de falsos positivos

### Opción 1 — Marca inline (en el propio código)
Añade `# IGNORE` al final de la línea que el escáner reporta como falso positivo:
```python
test_password = "testsecret"  # IGNORE
```

### Opción 2 — Registro persistente
Ejecuta el escáner en modo interactivo:
```bash
python3 scanner.py --mark-fp
```
Selecciona el número del hallazgo que quieres ignorar. Se guardará en `.false-positives` y **no volverá a reportarse**.

### Ver falsos positivos registrados
```bash
python3 scanner.py --list-fp
```

---

## 🔎 Patrones de detección

| Tipo                        | Severidad  |
|-----------------------------|------------|
| Contraseña hardcodeada      | HIGH       |
| Clave de API genérica       | HIGH       |
| Token / Secret genérico     | HIGH       |
| AWS Access Key              | CRITICAL   |
| AWS Secret Key              | CRITICAL   |
| Clave privada (PEM)         | CRITICAL   |
| Token GitHub (ghp_...)      | CRITICAL   |
| Token GitLab (glpat-...)    | CRITICAL   |
| Cadena de conexión a BD     | HIGH       |
| URL con credenciales        | MEDIUM     |
| Username hardcodeado        | LOW        |

---

## 📋 Requisitos

- Python 3.6+
- Git

No requiere librerías externas.

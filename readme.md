# 📖 VisorWeb PHP Seguro

Este proyecto es un **visor de contenidos web en PHP** diseñado con un fuerte enfoque en la **seguridad**, la **validación de archivos** y la **sanitización de datos**.  
Permite cargar y visualizar archivos locales (`.txt`, `.md`, `.json`) o incluso contenidos remotos desde URLs seguras (solo HTTPS), siempre bajo reglas estrictas que previenen inyecciones de código malicioso.

---

## 🔐 Características principales

- **Seguridad de sesiones**:
  - Cookies con `HttpOnly`, `SameSite=Strict` y soporte para `Secure`.
  - Modo estricto de uso de sesiones.

- **Protecciones contra ataques comunes**:
  - Bloqueo de dominios privados/inseguros (`localhost`, rangos privados, `file://`, `php://`, etc.).
  - Bloqueo de patrones peligrosos en nombres de archivo (`../`, `php://`, `ftp://`, etc.).
  - Sanitización de contenido para evitar ejecución de PHP, JavaScript o HTML no autorizado.

- **Gestión de archivos locales**:
  - Solo se permiten extensiones: `.txt`, `.md`, `.json`.
  - Límite máximo de tamaño: **2 MB por archivo**.
  - Validación para que los archivos estén siempre dentro del directorio permitido (`content/`).

- **Contenido remoto**:
  - Solo permite **URLs HTTPS válidas**.
  - Límite máximo de **1 MB** para archivos remotos.
  - Sanitización avanzada para evitar código malicioso.

- **Soporte de formatos**:
  - **Texto plano (`.txt`)** → Escapado seguro con saltos de línea.
  - **Markdown (`.md`)** → Soporte para:
    - Encabezados, listas, citas y tablas.
    - Negritas, cursivas, tachado, enlaces e imágenes.
    - Bloques de código con etiquetas de lenguaje.
  - **JSON (`.json`)** → Formateo estructurado con soporte para `title`, `description` y `sections`.

---

## 🚀 Flujo de funcionamiento

1. El usuario puede seleccionar un archivo local desde la carpeta `content/` o pasar una URL remota vía parámetro `?url=`.
2. El sistema valida:
   - Nombre del archivo o URL.
   - Extensión permitida.
   - Tamaño máximo.
   - Que no exista código PHP/JavaScript inyectado.
3. El contenido se procesa y se renderiza en HTML seguro.
4. En caso de error o intento de acceso indebido, se muestra un mensaje de advertencia sin comprometer la seguridad.

---

## ⚡ Ejemplos de uso

### Cargar archivo local

http://tusitio.com/visor.php?file=ejemplo.md

### Cargar contenido remoto seguro

http://tusitio.com/visor.php?url=https://raw.githubusercontent.com/usuario/repositorio/main/readme.md


---

## 📌 Casos de uso

- Crear un visor seguro de tutoriales o guías en formato Markdown.
- Integrar archivos JSON para mostrar información estructurada.
- Visualizar contenido externo desde fuentes confiables sin riesgo de ejecución de código malicioso.

---

## 🔒 Enfoque de seguridad

El diseño de este script prioriza la **prevención de ataques XSS, RFI, LFI y ejecución remota de código**.  
Todas las entradas del usuario son **filtradas, validadas y sanitizadas** antes de ser procesadas o renderizadas en el navegador.

---

✍️ Desarrollado por **Zidrave Labs** como parte del proyecto **VisorWeb**.

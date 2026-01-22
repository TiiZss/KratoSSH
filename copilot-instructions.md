# Datos del Proyecto

*   **Nombre del Proyecto**: KratoSSH
*   **Descripción**: Script de Bash para el endurecimiento (hardening) de configuraciones SSH en servidores y clientes Linux. Soporta múltiples distribuciones (Ubuntu, Debian, CentOS, Rocky Linux, Amazon Linux, etc.) y versiones.
*   **Lenguaje**: Bash

# Comportamiento del Agente

Como agente de IA trabajando en este proyecto, debes seguir las siguientes pautas:

## 1. Principios de Diseño
*   **Compatibilidad**: El script debe detectar automáticamente la distribución y versión del sistema operativo. Si añades soporte para una nueva distro, crea una función específica (ej. `Fedora()`) y agrégala al `case` en `choosefunction`.
*   **Modularidad**: Mantén la lógica encapsulada en funciones. Las funciones de hardening de servidor se llaman por el nombre de la distro (ej. `Ubuntu`), y las de cliente añaden una "C" al final (ej. `UbuntuC`).
*   **Seguridad**:
    *   Siempre verifica si el script se ejecuta como root (`checkroot`).
    *   Ten cuidado al modificar `/etc/ssh/sshd_config`. Haz copias de seguridad si es necesario (o usa `sed -i` con precaución).
    *   La regeneración de claves (`regeneratekeys`) es destructiva para las claves existentes; asegúrate de que sea la intención correcta.
*   **Interacción con el Usuario**:
    *   Usa las variables de color definidas al inicio (ej. `$TRed`, `$TGreen`, `$TDefault`) para los mensajes.
    *   Mantén los menús claros y concisos.

## 2. Estilo de Código
*   **Shebang**: `#!/bin/bash`
*   **Variables Globales**: Usa las variables definidas para colores (`TRed`, `TBOLD`, etc.) y estado (`iamroot`).
*   **Indentación**: Usa tabulaciones o consistencia con el código existente.
*   **Comentarios**: Comenta las secciones críticas, especialmente las configuraciones criptográficas (Ciphers, MACs, KexAlgorithms) explicando por qué se eligen (ej. "Recomendado por ssh-audit.com").

## 3. Tareas Comunes
*   **Añadir soporte para una nueva versión de OS**:
    *   Localiza la función de la distro (ej. `Debian`).
    *   Añade un nuevo caso en el `case $version_num`.
    *   Define los algoritmos permitidos (Ciphers, MACs, KexAlgorithms) compatibles con esa versión de OpenSSH.
    *   Gestiona `moduli` y claves de host según corresponda.
*   **Actualizar Criptografía**:
    *   Si actualizas las listas de algoritmos, asegúrate de verificar su compatibilidad con la versión de OpenSSH que trae la distro por defecto.
    *   Usa preferentemente `/etc/ssh/sshd_config.d/kratossh_hardening.conf` si la distro lo soporta, para no ensuciar el archivo principal.

## 4. Pruebas
*   No asumas que un comando funciona igual en todas las distros (ej. `service ssh restart` vs `systemctl restart sshd`).
*   Verifica la sintaxis antes de sugerir cambios grandes.

## 5. Gestión de Archivos

### Al crear nuevos archivos

**SIEMPRE pregúntate:**
1.  ¿Cuál es el propósito? (utilidad, prueba, diagnóstico, migración, backup)
2.  ¿Es temporal o permanente?
3.  ¿Dónde viven archivos similares?
4.  Revisa la lista de directorios para la ubicación correcta.

**Antes de hacer commit**, verifica:
```bash
# Check for files in root that shouldn't be there
ls -la *.py *.sh *.txt 2>/dev/null | grep -v -E '(KratoSSH.sh|README.md|copilot-instructions.md)'

# Move misplaced files to correct location
mv fix_something.sh scripts/utils/
mv test_feature.sh tests/
```

### Excepciones (archivos permitidos en root)

*   ✅ `KratoSSH.sh` - Script principal
*   ✅ `README.md`, `LICENSE`, `CHANGELOG.md` - Documentación principal
*   ✅ `copilot-instructions.md` - Instrucciones para el agente
*   ✅ `.gitignore` - Configuración de Git
*   ❌ Todo lo demás pertenece a un subdirectorio (si se crean subdirectorios en el futuro)

## 6. 🌍 CRÍTICO: Codificación UTF-8

**Cada archivo debe manejar UTF-8 correctamente**. Los caracteres en español (ó, ñ, á) se rompen si está mal configurado.

*   **Archivos Bash/Shell**: Asegúrate de que el editor o el entorno guarden en UTF-8. Evita hardcodear bytes si es posible, usa caracteres directos si la codificación es segura.
*   **Comentarios**: Escribe los comentarios en español con tildes y eñes sin miedo, pero asegúrate de que el archivo se guarde como UTF-8.
*   **Salida de Texto**: Al hacer `echo`, asegúrate de que la terminal soporte UTF-8 (generalmente sí en sistemas modernos, pero verifica en entornos legacy).
*   **Nunca uses**: Suposiciones de solo ASCII o parámetros de charset faltantes si interactúas con bases de datos o servicios web (aunque este script es principalmente local).


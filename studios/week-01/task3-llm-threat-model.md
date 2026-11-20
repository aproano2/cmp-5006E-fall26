# Tarea 3 — Modelo de amenaza generado por un LLM (evidencia)

Este archivo es la **entrada cruda del LLM**, sin editar. El análisis crítico
(qué acertó, qué inventó, dónde es fuerte y dónde débil) está en
`WRITEUP.md` §Tarea 3.

- **LLM:** Claude (Sonnet), vía Claude Code
- **Fecha:** 2026-08-31
- **Contexto dado al modelo:** el párrafo "El sistema, en una frase" de mi
  Tarea 2 (DVWA PHP + MySQL, Docker, `localhost`, `admin/password`, niveles
  `low`–`impossible`, módulos SQLi/XSS/command injection/file upload/CSRF/brute
  force/file inclusion/weak session IDs), **sin** mi diagrama, mis fronteras de
  confianza ni mi tabla STRIDE.

## Prompt exacto

> Eres un ingeniero de seguridad. Te doy la descripción de una aplicación web.
> Constrúyeme un modelo de amenaza STRIDE: diagrama de flujo de datos, fronteras
> de confianza, y al menos una amenaza por cada categoría de STRIDE, con una
> mitigación por amenaza. La app: DVWA (Damn Vulnerable Web Application), PHP +
> MySQL, se ejecuta en Docker sobre http://localhost, usuario único `admin` con
> contraseña `password`, con módulos para SQL injection, XSS, inyección de
> comandos, subida de archivos, CSRF, fuerza bruta, inclusión de archivos e IDs
> de sesión débiles, y un selector de nivel de seguridad low/medium/high/impossible.

---

## Respuesta del LLM (verbatim)

### 1. Descripción del sistema

DVWA es una aplicación web PHP respaldada por MySQL, desplegada como contenedor
Docker y expuesta en `http://localhost`. Ofrece una interfaz autenticada (sesión
por cookie) con un único usuario administrativo y una colección de módulos que
demuestran vulnerabilidades web comunes. Un ajuste global de "nivel de seguridad"
controla cuán rigurosas son las validaciones de cada módulo.

### 2. Diagrama de flujo de datos

```
+-------------+       HTTP/HTTPS        +----------------------+      SQL       +-----------+
|   Cliente   | <--------------------> |  Servidor web PHP     | <----------> |   MySQL   |
| (navegador) |   formularios, cookies |  (Apache + DVWA)      |   consultas  |  (datos)  |
+-------------+                         +----------------------+               +-----------+
                                          |            |
                                   sistema de     comandos del SO
                                   archivos       (exec/system)
                                   (uploads,      |
                                   inclusión)     v
                                          |   +-----------+
                                          |   |  Shell /  |
                                          +-->|  SO host  |
                                              +-----------+
```

### 3. Fronteras de confianza

- **TB1 — Cliente ↔ Servidor web:** el navegador está fuera de tu control; todo
  lo que llega (parámetros, cabeceras, cookies) es no confiable.
- **TB2 — Aplicación ↔ Base de datos:** las consultas se construyen en PHP y se
  ejecutan en MySQL.
- **TB3 — Aplicación ↔ Sistema operativo:** subida de archivos, inclusión de
  archivos y ejecución de comandos cruzan hacia el SO del contenedor.
- **TB4 — Contenedor ↔ Host Docker:** aislamiento del contenedor frente a la
  máquina anfitriona.
- **TB5 — Servicio de autenticación ↔ resto de la app:** la gestión de sesión
  separa a los usuarios anónimos de los autenticados.

### 4. Amenazas STRIDE

| STRIDE | Amenaza | Mitigación |
|---|---|---|
| **Spoofing** | Credenciales por defecto (`admin`/`password`) y ausencia de MFA permiten a cualquiera autenticarse como administrador. Fijación y secuestro de sesión por cookies sin `HttpOnly`/`Secure`. | Forzar cambio de contraseña en el primer inicio; implementar MFA; cookies con `HttpOnly`, `Secure`, `SameSite=Strict`; regenerar el identificador de sesión tras el login. |
| **Tampering** | Inyección SQL a través de parámetros de formulario permite modificar registros arbitrarios. CSRF permite que un sitio de terceros altere el estado en nombre del usuario. Manipulación de parámetros ocultos y de la cookie de nivel de seguridad. | Sentencias preparadas / consultas parametrizadas; tokens anti-CSRF por formulario y verificación del encabezado `Origin`/`Referer`; validación de entrada del lado servidor con listas de permitidos; firmar o mover a sesión del servidor los valores sensibles. |
| **Repudiation** | No hay registro de auditoría: un atacante que compromete la cuenta puede negar cualquier acción y no existe traza. | Registro centralizado e inmutable de eventos de autenticación y de cambios de estado, con marca de tiempo y dirección IP; envío de logs a un sistema externo (SIEM). |
| **Information disclosure** | Mensajes de error verbosos revelan consultas SQL y rutas del sistema. Inclusión de archivos locales (LFI) expone `/etc/passwd`, código fuente y `config.inc.php` con credenciales de BD. XSS reflejado y almacenado filtra cookies de sesión. Ausencia de TLS permite interceptar tráfico. | Desactivar `display_errors` en producción y mostrar páginas de error genéricas; validar y restringir las rutas de inclusión a un directorio fijo; codificación de salida contextual y CSP para XSS; forzar HTTPS con HSTS. |
| **Denial of service** | El módulo de fuerza bruta no aplica límites de tasa ni bloqueo de cuenta, permitiendo saturar el servidor. Subida de archivos grandes o inclusión recursiva agota disco/CPU. | Límite de tasa por IP y por cuenta; bloqueo temporal tras N intentos fallidos; CAPTCHA; límites de tamaño de subida; cuotas de CPU y memoria en el contenedor. |
| **Elevation of privilege** | Subida de un archivo `.php` (webshell) ejecutado por Apache otorga ejecución remota de código como el usuario web. La inyección de comandos da acceso directo al shell. Desde ahí, un contenedor mal configurado (privilegiado, con el socket de Docker montado, o corriendo como root) permite escapar al host. | Validar el tipo real del archivo y forzar extensiones seguras; almacenar los ficheros subidos fuera de la raíz web y sin permiso de ejecución; usar `escapeshellarg`/evitar `system()`; ejecutar el contenedor como usuario no privilegiado, sin capacidades extra y sin montar el socket de Docker; políticas seccomp/AppArmor. |

### 5. Recomendaciones prioritarias

1. Cambiar las credenciales por defecto y añadir MFA.
2. Migrar todas las consultas a sentencias preparadas.
3. Añadir tokens anti-CSRF globales.
4. Desactivar los errores verbosos y forzar HTTPS.
5. Endurecer la configuración del contenedor (no root, sin privilegios, límites
   de recursos).
6. Desplegar un WAF delante de la aplicación para mitigar clases de ataque
   conocidas mientras se corrigen las causas raíz.

### 6. Nota

DVWA es software educativo deliberadamente inseguro; en un entorno real ninguna de
estas vulnerabilidades debería estar presente. Mantenlo aislado de redes de
producción y no lo expongas a Internet.

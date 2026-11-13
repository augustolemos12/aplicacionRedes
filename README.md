# Servidor HTTP/1.1 Propio en Python — Redes de Información (UTN FRM)

Implementación educativa, funcional y auditable de un **servidor web HTTP/1.1 propio** construido directamente sobre **sockets TCP (`socket`)** y concurrencia por hilos (`threading`), utilizando exclusivamente la biblioteca estándar de Python 3.

Desarrollado para la asignatura **Redes de Información** de la carrera **Ingeniería en Sistemas de Información** (Universidad Tecnológica Nacional — Facultad Regional Mendoza).

---

## 1. Objetivo del proyecto y relación con la consigna

El trabajo práctico requiere implementar un servidor web que cumpla cinco pilares fundamentales sin recurrir a motores preexistentes como Apache, Nginx, Flask, Django ni `http.server`:

| Requisito de la Consigna | Implementación en este Proyecto |
| :--- | :--- |
| **1. Soporte para el protocolo HTTP** | Analizador (`server/http_parser.py`) y serializador (`server/response.py`) propios para un subconjunto documentado de **HTTP/1.1** (`GET`, `HEAD`, `POST`) sobre **TCP IPv4** (`server/socket_server.py`). |
| **2. Registro de información (logging)** | Módulo `server/logging_setup.py` que separa `logs/access.log` (tráfico HTTP) y `logs/error.log` (errores de protocolo, archivos inexistentes y eventos de seguridad), con sanitización contra *Log Injection*. |
| **3. Medidas de seguridad (`DocumentRoot`)** | Módulo `server/security.py` con decodificación controlada de URL, bloqueo de secuencias `../` (planas y codificadas en hexadecimal) y validación canónica mediante `Path.resolve()` + `is_relative_to(DocumentRoot)`. |
| **4. Interfaz de configuración vía web** | Panel web en `/admin` (`admin/dashboard.html`, `style.css`, `app.js`) servido por el **mismo servidor HTTP propio**, respaldado por endpoints JSON (`/admin/api/status`, `/admin/api/logs`, `POST /admin/api/config`) con protección CSRF. |
| **5. Protección de directorios con usuario y clave** | Esquema **HTTP Basic Authentication** (`RFC 7617`) sobre los directorios listados en `protected_directories` (por defecto `/private`) y sobre `/admin`, almacenando contraseñas con hash **PBKDF2-HMAC-SHA256** con sal aleatoria. |

---

## 2. Arquitectura general y responsabilidades de cada módulo

```text
aplicacionRedes/
├── main.py                      # Punto de entrada CLI, inicialización de credenciales y arranque ordenado
├── server/
│   ├── __init__.py
│   ├── socket_server.py         # Capa de transporte TCP: socket IPv4, bind, listen, accept, hilos y timeouts
│   ├── http_parser.py           # Capa de aplicación HTTP (entrada): lectura de flujo TCP, parseo de línea, headers y cuerpo
│   ├── response.py              # Capa de aplicación HTTP (salida): construcción binaria de respuestas y tipos MIME
│   ├── router.py                # Enrutamiento de recursos estáticos, formulario POST y API administrativa (/admin)
│   ├── security.py              # Controles de seguridad: anti-Path Traversal, HTTP Basic Auth, PBKDF2 y tokens CSRF
│   ├── config.py                # Carga, validación estricta de tipos/rangos y guardado de config/server.json
│   └── logging_setup.py         # Gestión de logs/access.log y logs/error.log con sanitización y lectura acotada
├── admin/
│   ├── dashboard.html           # Interfaz web administrativa (servida en GET /admin)
│   ├── style.css                # Estilos del panel administrativo
│   └── app.js                   # Cliente JS sin frameworks para consultar estado/logs y actualizar configuración
├── www/                         # DocumentRoot predeterminado (sitio web público de demostración)
│   ├── index.html               # Página de inicio con enlaces de prueba y formulario POST
│   ├── about.html               # Explicación de la arquitectura TCP/HTTP
│   ├── style.css                # Hoja de estilos estática (text/css)
│   ├── app.js                   # Script estático de prueba (application/javascript)
│   ├── logo.svg                 # Imagen vectorial (image/svg+xml)
│   ├── pixel.png                # Imagen binaria PNG para verificar transferencia binaria (image/png)
│   └── private/                 # Directorio protegido mediante usuario y contraseña
│       ├── index.html
│       └── confidential.html
├── config/
│   └── server.json              # Archivo de configuración persistente en formato JSON
├── logs/
│   ├── access.log               # Registro de solicitudes procesadas
│   └── error.log                # Registro de errores de protocolo, 404 y bloqueos de seguridad
├── tests/
│   ├── test_http_parser.py      # Pruebas unitarias del parser HTTP/1.1 y fragmentación TCP
│   ├── test_security.py         # Pruebas de Path Traversal, symlinks, PBKDF2, Basic Auth y Log Injection
│   └── test_server.py           # Pruebas de integración completas de extremo a extremo
├── README.md                    # Documentación técnica y guion de exposición
└── requirements.txt             # Detalle de biblioteca estándar (sin dependencias externas)
```

---

## 3. Tecnologías utilizadas y justificación

- **Python 3 (Biblioteca Estándar exclusivamente)**: Permite inspeccionar de primera mano la interacción entre el sistema operativo y la red sin cajas negras.
- **`socket`**: Provee acceso directo a la interfaz de sockets BSD del sistema operativo (`AF_INET`, `SOCK_STREAM`), permitiendo explicar `bind()`, `listen()`, `accept()`, `recv()`, `sendall()` y `close()`.
- **`threading`**: Implementa concurrencia mediante un hilo trabajador por conexión entrante (*thread-per-connection*), evitando que un cliente lento bloquee la atención de otros clientes.
- **`hashlib`, `hmac` y `secrets`**: Proveen primitivas criptográficas estándar (`pbkdf2_hmac` con SHA-256, comparación en tiempo constante `compare_digest` y generación de sales/tokens impredecibles).
- **`pathlib`**: Resuelve rutas de archivos de forma multiplataforma (Windows 11 y Linux/Fedora), resolviendo enlaces simbólicos y segmentos relativos con `Path.resolve()` e `is_relative_to()`.
- **HTML5, CSS3 y JavaScript Vanilla**: Para el sitio de prueba (`www/`) y el panel administrativo (`admin/`), sin frameworks externos ni pasos de compilación.

---

## 4. Diferencia entre TCP y HTTP en esta implementación

Un punto clave para la defensa oral es distinguir qué hace cada capa del modelo TCP/IP en el código:

1. **Capa de Transporte — TCP (`server/socket_server.py`)**:
   - Establece una conexión virtual punto a punto mediante el *Three-Way Handshake* (`SYN`, `SYN-ACK`, `ACK`) gestionado por el kernel del sistema operativo cuando el servidor ejecuta `listen()` y `accept()`.
   - Entrega un **flujo continuo de bytes sin estructura de mensajes** (*byte stream*).
   - **Implicancia en el código**: Una llamada a `client_sock.recv(4096)` **no garantiza** recibir una solicitud HTTP completa; puede entregar solo la mitad de los encabezados o parte del cuerpo de un `POST`.

2. **Capa de Aplicación — HTTP/1.1 (`server/http_parser.py` y `server/response.py`)**:
   - Define las reglas sintácticas y semánticas para delimitar mensajes sobre ese flujo TCP:
     - En `read_http_request()`, un bucle acumula bytes de `sock.recv()` hasta encontrar la secuencia delimitadora de fin de encabezados `\r\n\r\n` (`0x0D 0x0A 0x0D 0x0A`).
     - Una vez parseados los encabezados, si existe `Content-Length: N`, un segundo bucle continúa leyendo del socket hasta reunir exactamente los `N` bytes del cuerpo de la solicitud.
     - Al responder, el servidor envía `Connection: close`, indicando explícitamente que tras transmitir los bytes anunciados en el `Content-Length` de la respuesta se cerrará el socket TCP.

---

## 5. Flujo completo de una solicitud GET y una POST

### Flujo de una solicitud `GET /index.html`
1. El navegador abre una conexión TCP hacia `host:port` (por ejemplo, `127.0.0.1:8080`).
2. `TCPHTTPServer.serve_forever()` acepta la conexión con `accept()`, aplica `client_sock.settimeout(socket_timeout)` y lanza un hilo con `_handle_client_connection()`.
3. `read_http_request()` acumula bytes hasta `\r\n\r\n`, valida la línea `GET /index.html HTTP/1.1` y verifica que esté presente el encabezado `Host`.
4. `HTTPRouter.handle_request()` invoca `normalize_url_path()` y `resolve_safe_path()` en `server/security.py` para confirmar que la ruta no escapa de `www/`.
5. Verifica con `is_path_protected()` si la ruta requiere credenciales. Como `/index.html` es público, continúa.
6. `_serve_static_resource()` lee `www/index.html` en modo binario (`read_bytes()`), detecta el tipo MIME `text/html; charset=utf-8` y construye un objeto `HTTPResponse(status_code=200, ...)`.
7. `response.to_bytes()` serializa la línea de estado y encabezados en `iso-8859-1` seguidos de `\r\n\r\n` y concatena los bytes del archivo.
8. El servidor transmite todo con `client_sock.sendall()`, escribe el registro en `logs/access.log` y cierra el socket en el bloque `finally`.

### Flujo de una solicitud `POST /contacto`
1. Tras recibir hasta `\r\n\r\n`, `http_parser.py` lee el encabezado `Content-Length` (por ejemplo, `52`) y valida que no supere `max_request_size`.
2. Continúa leyendo del socket TCP hasta completar los 52 bytes del cuerpo (`alumno=...&comision=...`).
3. `router.py` verifica que el `Content-Type` sea `application/x-www-form-urlencoded`.
4. Decodifica el cuerpo en UTF-8, extrae los pares clave-valor con `urllib.parse.parse_qs` y sanitiza cada valor con `html.escape()` para prevenir inyección XSS.
5. Genera y devuelve una página HTML `200 OK` mostrando la tabla con los datos recibidos y la cantidad de bytes leídos.

---

## 6. Estructura de una solicitud y respuesta HTTP (Ejemplos reales)

### Ejemplo 1: Solicitud `GET` y Respuesta `200 OK`

**Solicitud enviada por el cliente:**
```http
GET /about.html HTTP/1.1
Host: localhost:8080
User-Agent: Mozilla/5.0
Accept: text/html

```

**Respuesta devuelta por nuestro servidor:**
```http
HTTP/1.1 200 OK
Date: Fri, 13 Nov 2026 13:00:00 GMT
Server: UTN-FRM-Redes-HTTP/1.0
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 3412
X-Content-Type-Options: nosniff

<!DOCTYPE html>
<html lang="es">
...
```

### Ejemplo 2: Acceso a directorio protegido `/private/` sin credenciales (`401 Unauthorized`)

**Solicitud enviada por el cliente:**
```http
GET /private/index.html HTTP/1.1
Host: localhost:8080

```

**Respuesta devuelta por nuestro servidor:**
```http
HTTP/1.1 401 Unauthorized
Date: Fri, 13 Nov 2026 13:01:10 GMT
Server: UTN-FRM-Redes-HTTP/1.0
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 924
X-Content-Type-Options: nosniff
WWW-Authenticate: Basic realm="Area protegida"

<!DOCTYPE html>...
```

### Ejemplo 3: Solicitud `POST` de formulario

**Solicitud enviada por el cliente:**
```http
POST /contacto HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 47

alumno=Estudiante+UTN&comision=Redes&mensaje=OK
```

---

## 7. Cómo iniciar el servidor en Windows y Linux

No se requiere instalar librerías externas. Asegúrese de contar con **Python 3.10 o superior**.

### Paso 1: Inicializar las credenciales del administrador
Por seguridad, el repositorio no incluye contraseñas en texto plano ni hashes precalculados universales en `config/server.json`. Antes del primer uso, elija una de estas dos opciones:

- **Opción A — Inicialización rápida para demostración de laboratorio** (configura usuario `admin` y contraseña `admin123` generando su hash PBKDF2 con sal aleatoria e inicia el servidor):
  ```bash
  python main.py --init-demo
  ```

- **Opción B — Definir una contraseña propia** (interactivo o por parámetro):
  ```bash
  python main.py --set-password
  ```
  O pasando la clave directamente:
  ```bash
  python main.py --set-password MiClaveSegura2026
  ```

### Paso 2: Iniciar el servidor
- **En Windows 11 (PowerShell o CMD)**:
  ```powershell
  python main.py
  ```
- **En Linux / Fedora**:
  ```bash
  python3 main.py
  ```

Para detener el servidor de manera ordenada en cualquier momento, presione **`Ctrl+C`** en la consola.

---

## 8. Cómo acceder desde la misma PC y desde otro equipo de la LAN

1. **Desde la misma computadora (`localhost`)**:
   - Sitio principal: `http://localhost:8080/`
   - Área protegida: `http://localhost:8080/private/`
   - Panel administrativo: `http://localhost:8080/admin`

2. **Desde otro equipo o teléfono en la misma red local (LAN)**:
   - Por defecto, el servidor escucha en `0.0.0.0:8080` (todas las interfaces IPv4).
   - Al iniciar `python main.py`, la consola muestra automáticamente la IP LAN detectada (por ejemplo, `http://192.168.1.105:8080/`).
   - **Nota sobre el Firewall del Sistema Operativo**:
     - En **Windows 11**: la primera vez que inicie Python escuchando en `0.0.0.0`, Windows Defender Firewall puede mostrar una ventana emergente; marque permitir en **Redes privadas**, o habilite el puerto `8080` TCP entrante.
     - En **Fedora / Linux**: si `firewalld` está activo, puede habilitar temporalmente el puerto con `sudo firewall-cmd --add-port=8080/tcp`.

---

## 9. Cómo configurar `host`, `port` y `DocumentRoot`

Puede modificar los parámetros de dos maneras:

1. **Vía Web desde el Panel Administrativo (`http://localhost:8080/admin`)**:
   - Ingrese con las credenciales de administrador.
   - Modifique los campos deseados y presione **"Validar y Guardar Configuración"**.
   - Los parámetros operativos (`max_request_size`, `socket_timeout`, `protected_directories`, `new_password`) se aplican **en caliente de forma inmediata**.
   - Los parámetros de enlace físico (`host`, `port`, `document_root`) se validan y guardan en `config/server.json`, y el panel muestra un aviso indicando que se aplicarán al reiniciar manualmente el proceso (`Ctrl+C` y `python main.py`).

2. **Editando directamente `config/server.json`**:
   ```json
   {
     "host": "0.0.0.0",
     "port": 8080,
     "document_root": "www",
     "admin_enabled": true,
     "max_request_size": 1048576,
     "socket_timeout": 10,
     "protected_directories": [
       "/private"
     ],
     "admin_username": "admin",
     "admin_password_hash": "pbkdf2_sha256$200000$..."
   }
   ```
   Si se introduce un valor inválido (por ejemplo, un puerto fuera de `1..65535` o un `document_root` fuera del proyecto), `server/config.py` rechaza la configuración con un mensaje descriptivo y evita que el servidor quede en un estado inconsistente.

---

## 10. Credenciales de administración y directorios protegidos

- **Almacenamiento seguro**: Las contraseñas nunca se guardan en texto plano. La función `hash_password()` en `server/security.py` genera una sal aleatoria de 16 bytes con `secrets.token_bytes(16)` y deriva un hash usando `hashlib.pbkdf2_hmac('sha256', password, salt, 200_000)`.
- **Verificación en tiempo constante**: Durante el login, `verify_password()` recalcula el hash y lo compara mediante `hmac.compare_digest()` para mitigar ataques de temporización (*timing attacks*).
- **Directorios protegidos**: Cualquier ruta listada en `protected_directories` (como `["/private"]`) exige el encabezado `Authorization: Basic <base64(usuario:contraseña)>` tanto para el directorio raíz como para todos sus archivos y subdirectorios descendientes.

---

## 11. Cómo ejecutar las pruebas automatizadas

El proyecto incluye una suite de **30 pruebas automatizadas** construidas con `unittest` en la carpeta `tests/` que verifican protocolo, fragmentación TCP, entrega binaria, seguridad, autenticación, CSRF y logs.

Ejecute desde la raíz del proyecto:

```bash
python -m unittest discover -s tests -v
```

*(Nota sobre enlaces simbólicos en Windows: la prueba `test_symlink_pointing_outside_document_root_blocked` intenta crear un symlink real en el sistema de archivos; si la cuenta de Windows no tiene activado el Modo Desarrollador / privilegio `SeCreateSymbolicLinkPrivilege`, `unittest` la reporta explícitamente como `skipped` indicando el código `WinError 1314`, mientras que `test_canonical_resolution_blocks_external_target_even_without_os_symlink_privilege` valida igualmente la lógica canónica `is_relative_to`).*

---

## 12. Cómo observar los logs

Los registros se guardan en la carpeta `logs/` con codificación UTF-8:

- **`logs/access.log`**: Registra cada solicitud procesada con fecha/hora, IP del cliente, línea de petición, código HTTP y bytes enviados:
  ```text
  [2026-11-13 10:20:15 -0300] 127.0.0.1 "GET / HTTP/1.1" 200 4120
  [2026-11-13 10:20:18 -0300] 127.0.0.1 "GET /private/index.html HTTP/1.1" 401 924
  ```
- **`logs/error.log`**: Registra errores de parseo, archivos no encontrados (`404`), fallos de autenticación (`401`) e intentos de ataque bloqueados (`403`):
  ```text
  [2026-11-13 10:20:25 -0300] [SECURITY_PATH_TRAVERSAL] [client 127.0.0.1] [target /%2e%2e/config/server.json] Intento de ruta maliciosa bloqueado: Intento de Path Traversal detectado (segmento '..' o '.').
  ```

También pueden consultarse en vivo desde el **Panel Administrativo (`http://localhost:8080/admin`)**, en el visor de solo lectura con selector de límite de líneas.

---

## 13. Medidas de seguridad implementadas

1. **Prevención de Path Traversal y escape del `DocumentRoot`**:
   - Decodificación iterativa de porcentajes URL (`%2e%2e`, `%252e%252e`) y bloqueo de bytes nulos (`%00`), barras invertidas (`\`) e identificadores de unidad (`C:`).
   - Resolución canónica con `Path.resolve()` y verificación estricta con `resolved_target.is_relative_to(canonical_doc_root)`, bloqueando también enlaces simbólicos que apunten hacia afuera.
2. **Deshabilitación de listado de directorios (*Directory Listing*)**:
   - Si se solicita un directorio que no posee `index.html`, devuelve `403 Forbidden` en lugar de exponer la estructura de archivos.
3. **Autenticación HTTP Basic con PBKDF2-HMAC-SHA256**:
   - Sal aleatoria de 128 bits, 200.000 iteraciones y comparación en tiempo constante (`hmac.compare_digest`).
4. **Protección de privacidad en Logs y Prevención de *Log Injection***:
   - Jamás se registran contraseñas ni el encabezado `Authorization`.
   - Todos los campos controlados por el cliente se sanitizan escapando `\r`, `\n`, `\t` y caracteres de control antes de escribirse en `access.log` o `error.log`.
5. **Protección del Panel Administrativo y Mitigación CSRF**:
   - Todas las rutas `/admin/*` requieren autenticación.
   - El endpoint `GET /admin/api/status` emite un token CSRF firmado con `HMAC-SHA256` y marca temporal (`CSRFTokenManager`), el cual es exigido en `POST /admin/api/config`.
   - No se expone `admin_password_hash` en las respuestas JSON ni se permite sobrescribir el hash con texto libre.
6. **Límites contra denegación de servicio básica**:
   - Timeout de lectura por socket (`socket_timeout`) y límite estricto de tamaño de encabezados y cuerpo (`max_request_size`), respondiendo `413 Content Too Large`.

---

## 14. Limitaciones conocidas (Por qué no es un servidor de producción)

Esta implementación fue diseñada con fines académicos para comprender el protocolo HTTP y los sockets TCP. **No debe exponerse directamente a Internet público** por las siguientes razones:

- **Ausencia de TLS / HTTPS**: El tráfico viaja en texto claro sobre TCP. En `HTTP Basic Auth`, las credenciales viajan codificadas en Base64 (fácilmente decodificables si alguien captura paquetes en tránsito fuera de una red controlada).
- **Subconjunto de HTTP/1.1**:
  - Procesa una solicitud por conexión (`Connection: close`); no implementa conexiones persistentes (*keep-alive*) ni *pipelining*.
  - No implementa `Transfer-Encoding: chunked` (responde explícitamente `501 Not Implemented`), compresión (`gzip`/`br`), rangos (`206 Partial Content`) ni encabezados condicionales de caché (`ETag`, `If-Modified-Since`).
- **Modelo de concurrencia simple**: Crea un hilo por conexión entrante. Aunque es ideal para claridad didáctica y pruebas en LAN, un servidor de producción emplea multiplexación de E/S asíncrona (`epoll`/`kqueue`/`IOCP`) o pools acotados de trabajadores frente a miles de conexiones simultáneas.

---

## 15. Guion breve de demostración para la exposición oral (5 a 7 minutos)

1. **Inicialización y arranque (Consola)**:
   - Ejecutar `python main.py --init-demo` y mostrar cómo el servidor enlaza el socket TCP en `0.0.0.0:8080`, informa la URL de `localhost` y de la red `LAN`, y aclara que la clave se guardó como hash PBKDF2 en `config/server.json`.
2. **Navegación pública y tipos MIME (`GET` — `200 OK`)**:
   - Abrir `http://localhost:8080/` en el navegador. Mostrar que se cargan HTML, CSS (`/style.css`), JS (`/app.js`), SVG (`/logo.svg`) y la imagen binaria `/pixel.png`.
   - Hacer clic en **"Arquitectura TCP/HTTP"** (`/about.html`) para apoyar la explicación oral de la diferencia entre flujo de bytes TCP y mensajes HTTP.
3. **Recurso inexistente (`404 Not Found`)**:
   - Hacer clic en el enlace de prueba **4. Recurso Inexistente (`/recurso-inexistente.html`)** y mostrar la página de error `404`.
4. **Bloqueo de Path Traversal (`403 Forbidden`)**:
   - Hacer clic en el enlace **5. Prueba de Path Traversal Codificado (`/%2e%2e/config/server.json`)** o ejecutar en otra terminal:
     ```bash
     curl -i --path-as-is http://localhost:8080/../config/server.json
     ```
   - Mostrar que el servidor bloquea el escape fuera de `www/` con `403 Forbidden`.
5. **Directorio protegido con HTTP Basic Auth (`401` -> `200`)**:
   - Abrir `http://localhost:8080/private/`. Mostrar el diálogo de credenciales del navegador (o probar con `curl -i http://localhost:8080/private/index.html` para ver el `401 Unauthorized` y el encabezado `WWW-Authenticate: Basic realm="Area protegida"`).
   - Ingresar `admin` / `admin123` y mostrar el acceso exitoso al contenido confidencial.
6. **Envío de formulario `POST` (`Content-Length`)**:
   - En la página de inicio, completar el formulario **"Demostración de Solicitud POST"** y enviarlo. Mostrar cómo el servidor lee el cuerpo según `Content-Length`, parsea `application/x-www-form-urlencoded` y devuelve la página con los campos sanitizados.
7. **Panel Administrativo y Logs (`/admin`)**:
   - Ingresar a `http://localhost:8080/admin`.
   - Mostrar las tarjetas de estado en vivo, cambiar `socket_timeout` (por ejemplo de `10` a `15` segundos), guardar y observar que se aplica inmediatamente.
   - Mostrar en el visor de logs del panel las entradas recién registradas tanto en `access.log` como en `error.log` (destacando que en ningún lugar aparece la contraseña ni el encabezado `Authorization`).
8. **Opcional — Captura con Wireshark**:
   - Seleccionar la interfaz *Adapter for loopback traffic capture* en Wireshark con el filtro `tcp.port == 8080`.
   - Realizar una petición `GET /about.html` y mostrar en vivo el *Three-Way Handshake* TCP (`SYN`, `SYN-ACK`, `ACK`), el paquete `HTTP GET`, la respuesta `HTTP/1.1 200 OK` y el cierre `FIN-ACK` motivado por `Connection: close`.

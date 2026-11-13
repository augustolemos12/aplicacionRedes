# Prompt maestro para Antigravity — Servidor HTTP propio en Python

Actuá como ingeniero de software senior y tutor técnico. Vas a diseñar e implementar, dentro del workspace abierto, un proyecto académico funcional: un **servidor HTTP propio escrito en Python**, acompañado por un panel web de administración. El proyecto es para la asignatura Redes de Información de Ingeniería en Sistemas de Información (UTN FRM).

Tu objetivo no es solamente producir código que funcione: también debés dejar una implementación comprensible, verificable y fácil de explicar en una exposición oral. Priorizá cumplir la consigna, la corrección de los fundamentos de redes y la seguridad básica por encima de agregar funcionalidades innecesarias.

## 1. Contexto y consigna

El trabajo práctico solicita implementar un servidor web con estas características:

1. Soporte para el protocolo HTTP.
2. Registro de información (logging).
3. Medidas de seguridad; se da como ejemplo bloquear el acceso a directorios/archivos que estén fuera del `DocumentRoot`.
4. Una interfaz para configurar los parámetros del servidor, que puede ser vía web.
5. Protección de directorios mediante usuario y contraseña.

La decisión acordada es **implementar un servidor HTTP propio en Python**, sin utilizar Apache, Nginx, Flask, Django ni `http.server` como motor del servidor principal. No se pide implementar el estándar HTTP completo: se implementará un subconjunto educativo, funcional y explícitamente documentado.

## 2. Decisiones técnicas ya acordadas

Respetá estas decisiones salvo que encuentres un impedimento técnico real. Si necesitás cambiar alguna, explicá primero el motivo y el impacto; no cambies la arquitectura silenciosamente.

- Lenguaje: Python 3.
- Servidor principal: biblioteca estándar `socket`; la comunicación TCP y el procesamiento HTTP deben estar implementados por el proyecto.
- Protocolo: subconjunto de HTTP/1.1.
- Modelo inicial: servidor concurrente mediante `threading`, con una conexión/solicitud por conexión y cierre explícito (`Connection: close`). No implementar keep-alive.
- Interfaz administrativa: HTML, CSS y JavaScript sin frameworks. Debe ser servida por el mismo servidor HTTP propio, en rutas administrativas.
- Backend administrativo: endpoints implementados en el propio servidor; no iniciar un segundo servidor web ni usar Flask.
- Logging: módulo estándar `logging`, con registros de acceso y errores separados.
- Configuración: archivo JSON legible y validado.
- Sin dependencias externas obligatorias. Preferir biblioteca estándar para mantener la instalación simple.
- Entorno objetivo inicial: Windows 11, pero mantener el código portable a Linux/Fedora siempre que sea razonable.
- Puerto predeterminado sugerido: `8080`, para no requerir privilegios administrativos.
- DocumentRoot predeterminado: carpeta `www/` dentro del proyecto.

## 3. Antes de modificar archivos

1. Inspeccioná el workspace actual y detectá si ya contiene archivos o código del proyecto.
2. No sobrescribas ni elimines archivos preexistentes sin comprobar su contenido y sin justificarlo.
3. Si el workspace está vacío, creá la estructura propuesta más abajo.
4. Si ya existe una estructura, adaptate a ella conservando el trabajo útil.
5. Antes de implementar, presentá un plan breve con los módulos, responsabilidades y orden de trabajo. Después avanzá con la implementación; no te detengas esperando aprobación para cada archivo.
6. No inventes resultados de pruebas. Ejecutá pruebas reales y reportá cuáles pasaron, cuáles fallaron y cuáles no pudieron ejecutarse.

## 4. Arquitectura y responsabilidades

Separá el sistema en módulos pequeños y con responsabilidades claras. Estructura de referencia:

```text
servidor-http/
├── main.py
├── server/
│   ├── __init__.py
│   ├── socket_server.py
│   ├── http_parser.py
│   ├── response.py
│   ├── router.py
│   ├── security.py
│   ├── config.py
│   └── logging_setup.py
├── admin/
│   ├── dashboard.html
│   ├── style.css
│   └── app.js
├── www/
│   ├── index.html
│   ├── about.html
│   └── private/
│       └── confidential.html
├── config/
│   └── server.json
├── logs/
│   ├── access.log
│   └── error.log
├── tests/
│   ├── test_http_parser.py
│   ├── test_security.py
│   └── test_server.py
├── README.md
└── requirements.txt
```

Podés ajustar nombres si mejora la coherencia, pero mantené la separación conceptual.

### 4.1. `main.py` y configuración

- Punto de entrada del programa.
- Carga y valida la configuración JSON.
- Inicializa el logging.
- Crea e inicia el servidor.
- Maneja el cierre ordenado con `Ctrl+C`.
- Muestra en consola la dirección y puerto donde escucha.
- No debe contener toda la lógica del servidor.

Configuración inicial sugerida:

```json
{
  "host": "0.0.0.0",
  "port": 8080,
  "document_root": "www",
  "admin_enabled": true,
  "max_request_size": 1048576,
  "socket_timeout": 10,
  "protected_directories": ["/private"],
  "admin_username": "admin",
  "admin_password_hash": ""
}
```

No guardes contraseñas en texto plano. Si se necesita inicializar el administrador, implementá un procedimiento claro de primer inicio o un comando/script de creación de credenciales. No dejes una contraseña universal conocida en producción. Para la demostración local, documentá cómo crear credenciales de prueba.

La configuración debe validarse: puerto dentro del rango permitido, límites positivos, DocumentRoot existente o creable según corresponda, tipos correctos y rutas coherentes. No permitas que una configuración inválida deje el servidor en un estado ambiguo.

### 4.2. `socket_server.py`: capa TCP

- Crear un socket TCP IPv4.
- Configurar `SO_REUSEADDR` cuando corresponda.
- Hacer `bind`, `listen` y `accept`.
- Escuchar por defecto en `0.0.0.0` para aceptar conexiones de otros equipos de la LAN; indicar que el firewall del sistema puede necesitar una regla para el puerto elegido.
- Atender clientes concurrentemente con `threading.Thread` o un mecanismo equivalente sencillo.
- Aplicar timeout a los sockets para evitar conexiones que queden bloqueadas indefinidamente.
- Limitar el tamaño máximo de solicitud.
- Gestionar desconexiones y errores de socket sin terminar todo el servidor.
- Para esta primera versión, procesar una solicitud HTTP por conexión y responder con `Connection: close`.
- Implementar cierre ordenado del socket y de los hilos cuando sea razonable.

No uses `socketserver`, `http.server`, `wsgiref`, frameworks ni servidores externos para resolver el núcleo del servidor. La intención académica es que el proyecto controle directamente el socket TCP.

### 4.3. `http_parser.py`: análisis HTTP

Implementá un analizador acotado, claro y defensivo para solicitudes HTTP/1.1.

Debe comprender la estructura:

```http
GET /index.html HTTP/1.1
Host: 192.168.1.100:8080
User-Agent: navegador
Accept: text/html

```

Requisitos:

- Separar línea de petición, encabezados y cuerpo.
- Reconocer método, target/ruta y versión.
- Interpretar encabezados sin distinguir mayúsculas/minúsculas en sus nombres.
- Manejar correctamente la separación CRLF (`\r\n`) del protocolo.
- Leer el cuerpo de solicitudes POST usando `Content-Length`.
- Detectar solicitudes incompletas, mal formadas o demasiado grandes.
- Rechazar versiones/métodos no soportados con respuestas HTTP apropiadas.
- No asumir que una llamada a `recv()` equivale a recibir un mensaje HTTP completo: TCP es un flujo de bytes. Acumular datos hasta completar encabezados y, cuando corresponda, el cuerpo, respetando límites y timeout.
- No implementar `Transfer-Encoding: chunked` en esta versión. Si llega una solicitud chunked, rechazarla de forma explícita y documentada, sin interpretar incorrectamente el cuerpo.
- Evitar parseos frágiles basados en posiciones fijas o supuestos no validados.

Representá la solicitud mediante una estructura sencilla (por ejemplo, dataclass) que contenga método, ruta, versión, encabezados y cuerpo.

### 4.4. `response.py`: respuestas HTTP

Centralizá la construcción y serialización de respuestas.

Como mínimo:

- Línea de estado HTTP/1.1.
- Encabezados `Date`, `Server`, `Content-Type`, `Content-Length` y `Connection: close` cuando correspondan.
- Separador CRLF entre encabezados y cuerpo.
- Cuerpo binario para poder servir imágenes, PDF, CSS, JavaScript y otros archivos sin corromperlos.
- Códigos y páginas de error coherentes.
- No enviar un cuerpo en respuestas donde no corresponda.
- Evitar concatenar texto y bytes de forma insegura.

Códigos mínimos a contemplar:

- `200 OK`
- `201 Created` si una operación administrativa lo necesita.
- `400 Bad Request`
- `401 Unauthorized`
- `403 Forbidden`
- `404 Not Found`
- `405 Method Not Allowed`
- `413 Content Too Large`
- `415 Unsupported Media Type` si corresponde.
- `500 Internal Server Error`
- `501 Not Implemented`
- `505 HTTP Version Not Supported`

Incluir `Content-Type` correcto según extensión. Para archivos desconocidos, usar `application/octet-stream`.

### 4.5. `router.py`: enrutamiento y recursos

Responsable de decidir qué hacer con cada solicitud.

- `GET /` debe servir `index.html`.
- `GET /about.html` debe servir la página de ejemplo.
- Servir archivos estáticos HTML, CSS, JavaScript, imágenes y otros archivos existentes bajo el DocumentRoot.
- `POST` debe estar implementado y demostrarse mediante un formulario sencillo de ejemplo. Puede procesar datos `application/x-www-form-urlencoded` y devolver una página o respuesta que muestre los datos recibidos. No hace falta crear una base de datos.
- Métodos no soportados deben devolver `405 Method Not Allowed` y un encabezado `Allow` coherente.
- Las rutas administrativas deben ser manejadas por el propio servidor y no confundirse con archivos arbitrarios del DocumentRoot.
- No permitir listados de directorios salvo que se implemente deliberadamente y se documente; por defecto, devolver `403` o servir un índice si existe.

### 4.6. `security.py`: seguridad

Esta parte es fundamental para cumplir la consigna. Implementá y probá, como mínimo, los controles siguientes.

**A. Protección del DocumentRoot / prevención de path traversal**

- Resolver la ruta solicitada de forma segura y comprobar que el destino final permanece dentro del DocumentRoot.
- Rechazar intentos como `../`, variantes codificadas (`%2e%2e`, `%2f`, etc.) y rutas absolutas que intenten escapar.
- Decodificar la ruta URL de manera controlada antes de resolverla.
- Considerar separadores de Windows y Linux.
- Usar rutas canónicas (`Path.resolve`) y comprobar pertenencia al DocumentRoot con una operación segura como `is_relative_to` o equivalente.
- Considerar enlaces simbólicos: el destino resuelto de un symlink tampoco puede escapar del DocumentRoot.
- No construir rutas de archivos concatenando directamente strings provenientes del cliente.
- Si se intenta acceder a un recurso fuera del DocumentRoot, devolver `403 Forbidden` y registrar el evento.

**B. Autenticación de directorios**

- Permitir declarar directorios protegidos en configuración, por ejemplo `/private`.
- Solicitar autenticación HTTP Basic al acceder a esos directorios y sus descendientes.
- Si faltan credenciales o son inválidas, devolver `401 Unauthorized` con `WWW-Authenticate: Basic realm="Area protegida"`.
- Validar credenciales de forma segura.
- Guardar contraseñas como hashes con sal usando una función estándar adecuada, por ejemplo `hashlib.pbkdf2_hmac`; comparar hashes con `hmac.compare_digest`.
- Nunca registrar contraseñas ni el encabezado `Authorization`.
- Documentar expresamente que Basic Auth sobre HTTP sin TLS transmite credenciales codificadas en Base64, no cifradas; sirve para una demostración en una LAN de laboratorio, no para proteger credenciales en Internet.
- No almacenar contraseñas en texto plano ni incluir credenciales reales en el repositorio.

**C. Panel administrativo**

- Las rutas administrativas y sus endpoints de modificación deben requerir autenticación.
- No exponer funciones de administración a clientes anónimos.
- Validar los datos recibidos antes de modificar la configuración.
- Evitar que el panel permita escribir archivos arbitrarios o cambiar rutas a ubicaciones peligrosas.
- Aplicar protección CSRF razonable para las operaciones POST del panel (por ejemplo, token por sesión o mecanismo equivalente). Si por el alcance elegido se utiliza una mitigación más simple, documentarla y explicar su limitación.
- No permitir que una petición HTTP desde el navegador cambie parámetros críticos sin validación.

### 4.7. Logging

Usá el módulo `logging` de Python.

Separá:

- `access.log`: fecha/hora, IP del cliente, método, ruta, versión HTTP, código de respuesta y tamaño enviado.
- `error.log`: errores de parsing, errores de socket, archivos inexistentes, accesos denegados y excepciones internas relevantes.

Requisitos:

- No registrar contraseñas, encabezados Authorization, cookies sensibles ni cuerpos que puedan contener datos privados.
- Evitar registrar información controlada por el usuario sin sanitizar saltos de línea, para prevenir log injection.
- La visualización de logs en el panel debe ser de solo lectura, limitada a una cantidad razonable de líneas y protegida por autenticación.
- Los errores internos no deben revelar trazas ni rutas del sistema al cliente; guardar el detalle técnico en error.log y devolver un error genérico.

### 4.8. Panel administrativo

El panel debe ser sencillo, funcional y estar servido por el mismo servidor HTTP.

Rutas sugeridas:

- `GET /admin`: muestra el panel, requiere autenticación.
- `GET /admin/api/status`: estado del servidor y configuración no sensible.
- `GET /admin/api/logs`: últimas líneas de los logs, con límite.
- `POST /admin/api/config`: actualiza parámetros permitidos, con validación.
- `POST /admin/api/restart`: si se implementa, debe explicar que el reinicio puede interrumpir la conexión actual. Es preferible que los cambios de host, puerto o DocumentRoot se apliquen al reiniciar manualmente el proceso, en lugar de intentar una reconfiguración en caliente compleja.

El panel debe permitir:

1. Consultar estado, host, puerto y DocumentRoot actual.
2. Consultar los logs recientes.
3. Modificar parámetros básicos de configuración.
4. Ver qué parámetros requieren reinicio.
5. Consultar/administrar la configuración de directorios protegidos si se implementa de forma segura.

No mostrar hashes de contraseñas ni secretos en el panel. No permitir cambiar el hash mediante un campo de texto libre. Si se incluye gestión de credenciales, que sea una operación específica y segura.

El panel debe incluir una indicación visible de que se trata de un servidor educativo y que HTTP sin TLS no es adecuado para uso público con credenciales.

## 5. Funcionamiento completo esperado

El flujo de una solicitud normal debe ser:

1. El cliente abre una conexión TCP al host y puerto del servidor.
2. El servidor acepta la conexión.
3. Recibe los bytes hasta completar encabezados y cuerpo según `Content-Length`.
4. El parser valida e interpreta la solicitud.
5. El router determina el recurso o endpoint.
6. La capa de seguridad valida ruta y autenticación.
7. El gestor de recursos obtiene el contenido o ejecuta la operación.
8. Se construye una respuesta HTTP válida.
9. Se envía la respuesta al cliente.
10. Se registra el resultado en `access.log`.
11. Se cierra la conexión.

Si ocurre un error, devolver el código HTTP apropiado cuando sea posible, registrar el detalle interno y cerrar correctamente la conexión.

## 6. Interfaz y contenido de demostración

Creá un sitio de prueba que permita demostrar el funcionamiento sin depender de Internet:

- `www/index.html`: página de inicio con el nombre del servidor y enlaces.
- `www/about.html`: página que explique brevemente que es un servidor HTTP educativo.
- Una página o formulario que envíe un POST y permita observar la respuesta.
- `www/private/index.html`: contenido protegido con autenticación.
- Recursos CSS/JS locales para comprobar que se sirven distintos tipos MIME.

La interfaz administrativa debe tener un diseño limpio, sobrio y entendible. No inviertas tiempo excesivo en diseño visual: priorizá claridad, accesibilidad y funcionamiento.

## 7. Pruebas obligatorias

Creá pruebas automatizadas con `unittest` (biblioteca estándar) o pruebas manuales reproducibles. Como mínimo, cubrí:

### Protocolo y parsing
- Parseo correcto de GET.
- Parseo correcto de POST con cuerpo y Content-Length.
- Encabezados con distintas mayúsculas/minúsculas.
- Solicitud mal formada.
- Solicitud incompleta o demasiado grande.
- Método no soportado.
- Manejo explícito de `Transfer-Encoding: chunked` no soportado.

### Servidor y respuestas
- GET a `/` devuelve `200`.
- GET a un archivo inexistente devuelve `404`.
- POST de formulario se procesa correctamente.
- Respuesta incluye Content-Type, Content-Length y Connection: close.
- Un archivo binario se sirve sin alterar sus bytes.

### Seguridad
- Ruta normal dentro del DocumentRoot permitida.
- Intento `../` bloqueado.
- Path traversal codificado bloqueado.
- Ruta absoluta fuera del DocumentRoot bloqueada.
- Symlink que apunta fuera del DocumentRoot bloqueado, si el sistema permite crear symlinks.
- Directorio protegido sin credenciales devuelve `401`.
- Credenciales incorrectas devuelven `401`.
- Credenciales correctas permiten acceso.
- Los logs no contienen contraseñas ni encabezados Authorization.

### Logging y administración
- Solicitud normal aparece en access.log.
- Error aparece en error.log.
- Rutas administrativas requieren autenticación.
- Configuración inválida es rechazada.
- Los logs del panel tienen límite de líneas.

Las pruebas deben poder ejecutarse con un comando documentado. Si alguna prueba depende del sistema operativo o de permisos especiales, indicar esa condición y no afirmar que pasó si no se ejecutó.

## 8. Requisitos de calidad y límites

- Código legible, con nombres descriptivos y comentarios donde expliquen decisiones no obvias.
- Type hints en funciones principales cuando aporten claridad.
- Manejo explícito de errores.
- No usar `eval`, `exec` ni ejecutar comandos del sistema construidos con datos del cliente.
- No introducir dependencias innecesarias.
- No crear funcionalidades de subida de archivos, proxy, CGI, TLS, WebSocket, HTTP/2, HTTP/3, compresión, caché, virtual hosts ni keep-alive salvo que sean imprescindibles; están fuera del alcance.
- No afirmar compatibilidad completa con HTTP/1.1. Documentar el subconjunto implementado y sus limitaciones.
- No exponer el servidor a Internet como si fuera seguro para producción. Es una implementación educativa.
- No dejar `TODO` en funcionalidades obligatorias.
- No ocultar excepciones generales sin registrarlas.
- Evitar que una solicitud maliciosa o inválida detenga el proceso completo.
- No hacer que el panel administrativo sea una segunda aplicación web con servidor independiente.

## 9. README y documentación para la exposición

El `README.md` debe estar escrito en español y explicar, con lenguaje claro:

1. Objetivo del proyecto y relación con la consigna.
2. Arquitectura general y responsabilidades de cada módulo.
3. Tecnologías utilizadas y por qué.
4. Diferencia entre TCP y HTTP en esta implementación.
5. Flujo de una solicitud GET y una POST.
6. Estructura de una solicitud y respuesta HTTP.
7. Cómo iniciar el servidor en Windows y Linux.
8. Cómo acceder desde la misma PC y desde otro equipo de la LAN.
9. Cómo configurar host, puerto y DocumentRoot.
10. Cómo crear/configurar credenciales de administración y directorios protegidos.
11. Cómo ejecutar las pruebas.
12. Cómo observar los logs.
13. Qué medidas de seguridad se implementaron.
14. Limitaciones conocidas y por qué no es un servidor de producción.
15. Guion breve de demostración para la exposición.

Incluí ejemplos concretos de solicitudes/respuestas HTTP. Explicá qué ocurre en el código, no te limites a listar archivos.

## 10. Guion de demostración sugerido

Prepará una secuencia de demostración que pueda ejecutarse en pocos minutos:

1. Iniciar el servidor y mostrar host/puerto en consola.
2. Abrir `http://localhost:8080/` y mostrar la página.
3. Abrir la misma dirección desde otro equipo de la LAN, si está disponible.
4. Solicitar una ruta inexistente y mostrar `404`.
5. Ingresar al directorio protegido sin credenciales y mostrar `401`; luego autenticar y mostrar el contenido.
6. Probar una ruta de path traversal y mostrar el bloqueo.
7. Enviar el formulario POST y mostrar el resultado.
8. Abrir el panel administrativo y mostrar configuración y logs.
9. Mostrar en `access.log` las solicitudes recién realizadas.
10. Si hay tiempo, capturar una solicitud y respuesta HTTP con Wireshark, identificando el flujo TCP y los mensajes HTTP.

No dependas de tener dos computadoras para que la demostración principal funcione: todo debe poder probarse también en `localhost`.

## 11. Método de trabajo que debés seguir

Trabajá por etapas, pero completá el proyecto. No te limites a generar un plan o un esqueleto.

**Etapa 1 — Inspección y diseño**
- Inspeccionar workspace.
- Crear o adaptar estructura.
- Identificar riesgos técnicos.
- Presentar un resumen del diseño.

**Etapa 2 — Núcleo HTTP**
- Implementar socket TCP.
- Implementar recepción robusta de bytes.
- Implementar parser HTTP.
- Implementar respuestas.
- Implementar entrega de archivos estáticos.
- Probar GET y errores básicos.

**Etapa 3 — Seguridad y logging**
- Implementar resolución segura de rutas.
- Implementar autenticación de directorios.
- Implementar logs de acceso y errores.
- Ejecutar pruebas de seguridad.

**Etapa 4 — POST y administración**
- Implementar formulario POST de ejemplo.
- Implementar panel y endpoints administrativos dentro del mismo servidor.
- Proteger y validar las operaciones administrativas.
- Probar cambios de configuración y logs.

**Etapa 5 — Validación y entrega**
- Ejecutar todas las pruebas.
- Corregir fallos.
- Verificar inicio y uso en Windows.
- Completar README y guion de exposición.
- Entregar un resumen de archivos creados, funcionalidades terminadas, comandos para ejecutar y resultados reales de pruebas.

Al terminar cada etapa, informá brevemente qué quedó implementado y qué pruebas ejecutaste. No esperes mi autorización entre etapas salvo que exista una decisión que realmente requiera información mía.

## 12. Criterio final de aceptación

El proyecto se considera listo cuando:

- Se inicia mediante un comando sencillo.
- Un navegador puede conectarse al servidor Python por TCP.
- El servidor interpreta solicitudes HTTP y responde correctamente para el subconjunto documentado.
- Sirve recursos estáticos, incluidos archivos binarios.
- Procesa al menos un POST de formulario.
- Registra accesos y errores.
- Impide salir del DocumentRoot mediante rutas manipuladas.
- Protege un directorio mediante usuario y contraseña.
- Incluye un panel web protegido para consultar estado, configuración y logs.
- La configuración se puede modificar mediante el panel o archivo de configuración, con validación y aplicación de cambios documentada.
- Las pruebas principales pasan.
- El README permite instalar, ejecutar, probar y explicar el proyecto.

**Instrucción final:** implementá el sistema con criterio de alcance. Si el tiempo o la complejidad obligan a priorizar, asegurá primero el núcleo TCP/HTTP, el servicio de archivos, logging y seguridad exigida por la consigna. Después completá el panel administrativo. No reemplaces el servidor propio por Apache, Flask, Django o `http.server`. No sacrifiques la comprensión del proyecto por agregar características visuales. El resultado debe ser funcional, demostrable y técnicamente honesto respecto de lo que implementa y lo que no.

# Week 1 Studio — Writeup

**Autor:** James S. V. (james25sv@gmail.com)
**Fecha:** 2026-08-27 (Tarea 1) · 2026-08-31 (Tareas 2–3)
**Evidencia reproducible:** `python3 test_cipher.py` (4/4 pasan), `python3 starter.py`,
`python3 _evidence.py`. Tarea 3: entrada cruda del LLM en `task3-llm-threat-model.md`.

---

## Tarea 1 — Romper el cifrado

### 1. Plaintext recuperado y precisión pre-corrección

El ataque solo ve el ciphertext y el conocimiento público del inglés
(`ENGLISH_FREQ`, `score`). Nunca toca la clave ni el plaintext.

| Corpus | Pase solo-frecuencias | Hill-climb de bigramas |
|---|---|---|
| 12 ciphertexts ingleses (582 chars c/u, key seeds 1–12) | **31 %** de caracteres | **100 %** |
| Control no-inglés (plaintext uniforme aleatorio) | — | **9 %** |

Plaintext recuperado (`english[0]`, sin la clave, sin corrección a mano):

> SECURITY THROUGH OBSCURITY IS THE RELIANCE ON SECRECY OF DESIGN AS THE MAIN
> METHOD OF PROVIDING SECURITY FOR A SYSTEM. A SYSTEM RELYING ON OBSCURITY MAY
> HAVE REAL SECURITY VULNERABILITIES, BUT ITS OWNERS OR DESIGNERS BELIEVE THAT IF
> THE FLAWS ARE NOT KNOWN THEN ATTACKERS WILL BE UNLIKELY TO FIND THEM. …

**De dónde sale la señal extra (31 % → 100 %).** El pase de frecuencias usa
estadística de *una letra* y sobre un único texto de 582 caracteres varias letras
de frecuencia parecida quedan traspuestas (O/I/N, D/L, Y/P…), y cada
transposición arrastra todas sus ocurrencias. El hill-climb añade la estadística
de *pares de letras*: `score` premia bigramas ingleses frecuentes (`TH`, `HE`,
`IN`, `ER`) y castiga los imposibles (`QX`, `JZ`). Esa estructura de bigramas
**sobrevive intacta a la sustitución** aunque no puedas leer las letras: una
sustitución monoalfabética es una biyección, así que si el símbolo `X` sigue a
`Q` con la misma frecuencia con que `H` sigue a `T` en inglés, el par se puede
identificar por su *comportamiento posicional* sin conocer su valor. El
hill-climb solo busca la permutación que maximiza ese parecido — unas pocas miles
de evaluaciones de `score`, no las 26! ≈ 4×10²⁶ claves.

### 2. La suposición (una frase)

> El ataque asumió que **el texto plano es prosa inglesa con las frecuencias de
> letras y de bigramas estándar del idioma** — la suposición no declarada del
> diseñador de que "el plaintext no tiene estructura explotable" — y es
> exactamente esa suposición, no ninguna debilidad del algoritmo, la que colapsa
> un espacio de claves de 4×10²⁶ a una búsqueda local guiada por estadística
> pública.

Esto es Kerckhoffs: la garantía de confidencialidad nunca dependió de que el
algoritmo fuera secreto, sino de una condición sobre el plaintext que el diseño
jamás enunció. El test `test_english_assumption_collapses_confidentiality` la ve
caer en las 12 claves; `test_cipher_holds_on_non_english_plaintext` muestra el
reverso — con el mismo ataque y un plaintext sin estructura, la recuperación cae
al 9 %.

### 3. Derrota tu propio ataque — defensa en términos del eje 2

**Defensa:** comprimir el mensaje con DEFLATE (`zlib`) y re-alfabetizarlo a A–Z
(base32) *antes* de aplicar la sustitución. La compresión elimina la redundancia
del idioma: el flujo comprimido se acerca a la equiprobabilidad de símbolos, así
que el análisis de frecuencias de letras y de bigramas se queda sin señal
lingüística que morder.

Evidencia (`_evidence.py`): sobre 4 mensajes comprimidos + base32 (~170
caracteres cada uno), el hill-climb recupera **13–21 %** de la forma de
transporte — el mismo rango que el control aleatorio (9 %). El ranking de letras
de la muestra ya no correlaciona con `ENGLISH_FREQ`.

| Eje del Control Scorecard | Antes (sustitución sola) | Con la defensa | Evidencia |
|---|---|---|---|
| 1 · Modelo de amenaza | Atacante con el ciphertext y conocimiento público del inglés; sin la clave | Sin cambios | `test_cipher.py` |
| 2 · **Garantía** | Ninguna frente a plaintext inglés | **El análisis de frecuencias de letras/bigramas no dispone de señal lingüística explotable, _bajo la condición_ de que (a) el atacante no modele la distribución de símbolos del formato comprimido y (b) los mensajes sean suficientemente largos para que la compresión sea efectiva.** No garantiza confidencialidad contra un atacante que conozca el códec. | `_evidence.py` |
| 3 · Cobertura | 0/12 textos resisten | 4/4 mensajes comprimidos resisten el hill-climb con `crack_seed=1`, recuperación 13–21 % (muestra pequeña, no el espacio) | `_evidence.py` |
| 4 · **Bypass** | El ataque *es* el bypass | El encabezado de zlib es constante y predecible (`78 9C…`); un atacante que sepa que hay compresión puede recortar prefijo/sufijo conocidos y atacar el resto, o explotar fugas de longitud/ratio (estilo CRIME) si controla parte del plaintext. **No intenté implementar este bypass** — es la limitación principal. | — |
| 5 · Coste — falsos positivos | 0 | La descompresión falla en bloque ante un solo bit corrupto: sin integridad previa, un error de transmisión destruye todo el mensaje (no solo un carácter, como en la sustitución) | `_evidence.py` (forma de transporte) |
| 6 · Coste — operativo | Ninguno (lápiz y papel) | Emisor y receptor deben compartir e implementar el códec; ~+40 % de longitud del texto por el base32; ya no es un cifrado manual | — |
| 7 · Observabilidad | N/A | N/A — sigue sin haber log de decisión | — |
| 8 · Modo de fallo | Falla abierto (plaintext legible) | Falla cerrado hacia el receptor legítimo (mensaje ilegible si algo se corrompe); **falla abierto** frente al atacante que modela el formato | — |

*"Ahora es más difícil" no es la garantía — la garantía es la fila del eje 2 con
su condición.*

### 4. Failure Atlas — texto corto que el análisis de frecuencias resuelve mal

**Caso (el más instructivo):**

```
plaintext : THE JAZZ QUARTET PLAYED A QUICK WALTZ FOR THE QUEEN.   (52 caracteres)
freq-only : TSE DAOO INAHTET LRACEU A INMWF GARTO YPH TSE INEEB.
recuperado: 50 %   —   17 de 20 símbolos mal mapeados
```

**Por qué falla.** En una muestra de 52 caracteres las frecuencias de la
población no se cumplen: esta frase está deliberadamente cargada de letras raras.

| Letra | Rango en la muestra | Rango en `ENGLISH_FREQ` (población) |
|---|---|---|
| `Z` | 4.º (3 ocurrencias: JA**ZZ**, WALT**Z**) | 26.º (0.07 %) |
| `Q` | 5.º (3: **Q**UARTET, **Q**UICK, **Q**UEEN) | 24.º (0.10 %) |
| `U` | alto (sigue siempre a Q) | 21.º |
| `O`, `I`, `N` | ausentes o casi | 4.º / 5.º / 6.º |

El pase de frecuencias solo ordena por conteo. Como en *esta* muestra `Z` y `Q`
aparecen mucho, sus símbolos cifrados se mapean a letras frecuentes del inglés
(en la corrida real: el símbolo de `Z` recibe `O`, el de `Q` recibe `I`). En
espejo, letras que la población tiene como comunes (`O`, `I`, `N`) casi no salen
en 52 caracteres y quedan hundidas en el ranking. Resultado: 17 de 20 símbolos
mal asignados, recuperación del 50 %.

Un segundo caso más extremo (`QUIZ VEXED NYMPH.`, 17 caracteres) baja al **29 %**:
con tan pocos datos, 12 de 13 símbolos quedan mal.

**Lección:** el análisis de frecuencias no "conoce el inglés", solo asume que
*esta muestra* se comporta como el idioma promedio. En textos cortos esa
asunción se rompe primero en las letras raras — que es justo donde el hill-climb
de bigramas tampoco tiene mucho contexto para corregir.

---

## Tarea 2 — Modelo de amenaza STRIDE (objetivo DVWA de la semana 0)

> Usa `../../resources/threat-model-template.md`. Este modelo es el mapa que
> pondrás a prueba en la semana 6 — commitéalo.

### El sistema, en una frase

**DVWA (Damn Vulnerable Web Application)** es una aplicación web PHP + MySQL
deliberadamente vulnerable, pensada para practicar ataques web contra un objetivo
propio. Se ejecuta en local con Docker (`ghcr.io/digininja/dvwa`) sobre
`http://localhost`, y el único usuario legítimo es el estudiante, autenticado como
`admin` con la contraseña por defecto `password`. Cada módulo (SQLi, XSS, inyección
de comandos, subida de archivos, CSRF, fuerza bruta, inclusión de archivos, IDs de
sesión débiles) implementa el mismo fallo en cuatro niveles de seguridad
seleccionables — `low`, `medium`, `high`, `impossible`.

**Supuestos de este modelo** (lo modelo "desde afuera", como pide la plantilla):
nivel de seguridad **`low`** (el de arranque), imagen oficial sin modificar,
contenedor con la configuración por defecto de Docker, MySQL solo accesible desde
dentro del contenedor. Aunque el objetivo real corre en `localhost`, lo modelo
como si el navegador estuviera al otro lado de una red no confiable, porque es la
postura que voy a atacar en la semana 6.

### Diagrama de flujo de datos

```
   [ Navegador ]                    ← el atacante controla esto; no se confía en nada de aquí
        │  HTTP: parámetros GET/POST de formulario, cookies PHPSESSID + `security`
════════╪═══════════════════ FC1: red / navegador ↔ servidor ══════════════════════════════
        ▼
   [ Apache + PHP · DVWA ] ══ FC2 ══ consulta SQL (mysqli) ══▶ [ MySQL: tabla `users`, hashes ]
        │        │
        │        ╠═ FC3 ═ lee / escribe archivos ════════════▶ [ FS: /var/www/html/hackable/uploads,
        │        │                                                config/config.inc.php ]
        │        ╚═ FC3 ═ system() / shell_exec() ═══════════▶ [ shell del SO (usuario web) ]
════════╪═══════════════════ FC4: contenedor ↔ host ═══════════════════════════════════════
   [ Host Docker ]  ──▶ kernel, otros contenedores, red del host

   FC = frontera de confianza (ver lista abajo). FC1 = navegador↔servidor,
   FC2 = app↔MySQL, FC3 = app↔shell/FS, FC4 = contenedor↔host.
```

### Fronteras de confianza

Cada línea marca dónde los datos cruzan de algo que no controlo a algo que sí (o
al revés). *Casi toda vulnerabilidad real de DVWA vive sobre una de estas líneas.*

1. **Navegador ↔ servidor web** — el atacante envía cualquier petición, con
   cualquier parámetro y cualquier cookie; nadie garantiza el formato ni el
   contenido, y en `low` no hay TLS que impida leer/alterar en tránsito.
2. **App PHP ↔ MySQL** — la app construye consultas a partir de entrada del
   usuario; la base de datos ejecuta lo que reciba, sin distinguir dato de código.
3. **App PHP ↔ shell / sistema de archivos** — módulos como *Command Injection*
   pasan entrada del usuario a `system()`, y *File Upload* escribe en una carpeta
   servida por Apache.
4. **Contenedor DVWA ↔ host Docker** — si el atacante logra ejecutar código como
   usuario web, esta frontera es lo único que queda entre él y el host.

### Una amenaza por categoría STRIDE

Las dos columnas que cargan la nota son *Garantía — y su condición (eje 2)* y
*Evidencia*. "No probado aún — semana 6" es una entrada honesta y válida: dice al
lector dónde mirar.

| # | Amenaza (letra) | Dónde entra | Qué gana el atacante | Mitigación | Garantía — y su condición (eje 2) | Evidencia |
|---|---|---|---|---|---|---|
| 1 | **S**poofing | Formulario de login / cookie de sesión (frontera 1) | Actuar como `admin` sin conocer la contraseña | Cambiar credenciales por defecto; IDs de sesión de un CSPRNG; cookies `HttpOnly` + `Secure` + `SameSite`; regenerar el ID al autenticar | Una cookie de sesión **no puede predecirse ni reproducirse** — *siempre que* los IDs vengan de un CSPRNG y se fuerce TLS. El nivel `impossible` de DVWA cumple; en `low`/`medium` el módulo *Weak Session IDs* emite IDs secuenciales y sin flags → la garantía **no se sostiene**. | No probado aún — semana 6 |
| 2 | **T**ampering | Parámetro `?id=` del módulo SQLi → consulta SQL (frontera 2) | Reescribir la cláusula `WHERE`: leer o modificar cualquier fila, volcar `users` con los hashes | Consultas parametrizadas (sentencias preparadas con parámetros ligados) en **toda** consulta | La entrada **nunca puede interpretarse como SQL** — *siempre que* cada consulta use parámetros ligados y no haya concatenación de cadenas en ningún punto del código. Se cumple en `impossible`; en `low` la consulta concatena `$id` directamente. | No probado aún — semana 6 |
| 3 | **R**epudiation | Cualquier acción autenticada (frontera 1) | Negar lo hecho: DVWA no registra ni logins ni acciones, no hay forma de atribuir un cambio | Log de auditoría append-only (usuario, IP de origen, acción, marca de tiempo) escrito **antes** de confirmar la acción y enviado fuera de la máquina | Toda acción que cambia estado es **atribuible** — *siempre que* el log se escriba antes del commit y se almacene donde el usuario de la app no pueda editarlo. DVWA **no aporta ninguno** → sin garantía. | N/A — ausente por diseño |
| 4 | **I**nformation disclosure | Respuestas de error y URLs directas (frontera 1) | Aprender esquema, nombres de tablas/columnas, usuario de BD, rutas de archivos → acelera los demás ataques | Página de error genérica; `display_errors = Off` en producción; detalles solo al log del servidor; denegar acceso directo a `config/` y `setup.php` | Ni el texto de la consulta ni las rutas internas **llegan al cliente** — *siempre que* el modo depuración esté apagado en la imagen desplegada. DVWA se distribuye con `display_errors` activo y devuelve el error MySQL crudo en `low`. | No probado aún — semana 6 |
| 5 | **D**enial of service | Formulario de login del módulo *Brute Force*; campo del módulo *Command Injection*; formulario de subida (fronteras 1 y 3) | Dejar la app inservible para uso legítimo | Límite de tasa + bloqueo de cuenta tras N intentos; tope de tamaño de petición; límites de CPU/memoria del contenedor (`--cpus`, `--memory`) | Ningún cliente puede consumir más de X peticiones/s o Y MB — *siempre que* los límites se apliquen en el proxy **y** en el contenedor. DVWA no tiene límite de intentos ni lockout, y Docker por defecto no limita recursos → sin garantía. | No probado aún — semana 6 |
| 6 | **E**levation of privilege | Formulario de subida → `/hackable/uploads` (frontera 3); de shell de usuario web → frontera 4 | Ejecución de código como usuario web; potencial escape del contenedor al host | Validar el archivo por su contenido, no por extensión; guardarlo **fuera** del directorio servido; montar el almacén `noexec`; contenedor como usuario no-root, sin socket de Docker, con `seccomp`/`cap-drop` | Un archivo subido **nunca puede ejecutarse como código** — *siempre que* se almacene fuera de la ruta servida por Apache y ese volumen esté montado `noexec`. En `low` DVWA acepta `.php` y Apache lo sirve como ejecutable → la garantía **no existe**. | No probado aún — semana 6 |

### Lo que no pude determinar desde afuera

No sé con certeza en qué nivel de seguridad correrá el objetivo de la clase en la
semana 6, si el contenedor se ejecuta como `root` o monta el socket de Docker
(lo que convertiría la amenaza 6 en un escape trivial al host), si MySQL está
expuesto más allá del contenedor, ni qué versión de PHP trae la imagen (y por
tanto qué CVEs conocidos aplican). Para saberlo necesitaría revisar el
`docker-compose.yml` / los flags de `docker run`, la salida de `php -v` y
`phpinfo.php`, y el usuario y las capacidades del contenedor (`docker inspect`).

---

## Tarea 3 — El ángulo IA

> Entrega la descripción de la app a un LLM, pídele que la modele. Compara con
> la cláusula de honestidad del scorecard.

**LLM:** Claude (Sonnet), 2026-08-31. Le di **solo** el párrafo "El sistema, en
una frase" de mi Tarea 2 — no mi diagrama, ni mis fronteras, ni mi tabla. La
salida cruda y el prompt están en [`task3-llm-threat-model.md`](task3-llm-threat-model.md).

### Qué encontró que se me pasó

- **CSRF.** Mi tabla de una-amenaza-por-letra metió toda la manipulación en SQLi y
  dejó fuera el CSRF, que es un módulo propio de DVWA y una amenaza de *Tampering*
  distinta (el atacante no toca la BD directamente: hace que la víctima autenticada
  la toque por él). El LLM lo puso con su token anti-CSRF + verificación de
  `Origin`/`Referer`.
- **Inclusión de archivos local (LFI).** No aparecía en mi modelo. El LLM señaló
  que `?page=` sin restringir permite leer `/etc/passwd`, el código fuente y
  `config/config.inc.php` **con las credenciales de MySQL en claro** — que es
  justamente lo que convierte una fuga de información en escalada hacia la
  frontera 2.
- **XSS como vector de robo de sesión.** Yo traté el robo de cookie solo como
  "IDs de sesión débiles". El LLM conectó XSS almacenado → exfiltración de
  `PHPSESSID` → *Spoofing*, que es una cadena más realista que adivinar el ID.
- **La cookie `security` es entrada controlada por el cliente.** El LLM la
  menciona de pasada ("manipulación de la cookie de nivel de seguridad"); yo la
  di por hecha. El nivel de seguridad viaja en una cookie que el navegador puede
  editar — un detalle específico de DVWA que debilita cualquier razonamiento del
  tipo "en `impossible` esto está bien".

### Qué afirmó que es falso (o engañoso) para *mi* app concreta

- **"Implementar MFA", "forzar cambio de contraseña en el primer login".** DVWA
  no tiene flujo de registro, ni de recuperación, ni gestión de usuarios: hay un
  único usuario en una tabla `users` semilla. La recomendación es de manual de
  SaaS, no aplica a esta app.
- **"Desplegar un WAF delante de la aplicación."** Es exactamente el
  *"añadimos un WAF, estamos protegidos"* que el Control Scorecard existe para
  desmontar. Trata el síntoma, no la causa, y no viene con condición ni con
  coste (eje 2, eje 5). En el contexto del curso es una respuesta equivocada.
- **`SameSite=Strict` como mitigación de fijación de sesión.** Mezcla dos cosas:
  `SameSite` ayuda contra CSRF, no contra fijación; la fijación se corrige
  regenerando el ID al autenticar (que el LLM también menciona, pero las agrupa
  como si fueran la misma defensa).
- **"Migrar todas las consultas a sentencias preparadas" como si fuera un
  arreglo.** DVWA es vulnerable **a propósito**; el `impossible` ya usa PDO
  parametrizado. El LLM modela DVWA como una app de producción que hay que
  asegurar, cuando el objetivo del ejercicio es atacarla y entender la condición
  bajo la que cada nivel se sostiene.
- **`escapeshellarg` para inyección de comandos.** Es una mitigación real, pero
  el LLM no dice que en `low` DVWA ni siquiera separa los argumentos — la afirma
  como si bastara, sin la condición "y no volver a concatenar en la cadena del
  comando".

### Dónde es más fuerte: amplitud / checklist

Enumeró en segundos el catálogo completo estilo OWASP —CSRF, LFI/RFI, XSS
reflejado/almacenado, fuerza bruta sin lockout, errores verbosos, falta de TLS,
webshell vía subida, escape de contenedor— sin olvidar ninguna categoría STRIDE.
Mi tabla, limitada a una amenaza por letra, comprimió y perdió CSRF y LFI. Como
**lista de verificación de "¿me dejé algo?"** es claramente superior a mi primera
pasada.

### Dónde es más débil: mis fronteras de confianza específicas

- **La frontera 4 (contenedor ↔ host) la trata en abstracto.** Dice "un
  contenedor mal configurado (privilegiado, con el socket montado, corriendo como
  root)" — que es una disyunción de posibilidades genéricas, no una pregunta
  sobre *mi* despliegue. Mi sección "Lo que no pude determinar" es más útil
  porque nombra el comando concreto (`docker inspect`) que hay que correr para
  cerrar esa incógnita.
- **Ninguna garantía viene con su condición (eje 2).** Todas sus mitigaciones son
  imperativos sueltos ("usar consultas parametrizadas", "validar la entrada"),
  nunca "X garantiza Y **siempre que** Z". Es precisamente el tipo de afirmación
  a medias que el scorecard penaliza.
- **No razona sobre niveles.** DVWA es interesante porque el *mismo* código está
  roto en `low` y bien en `impossible`; el LLM da una sola recomendación por
  amenaza sin atarla al nivel, que es donde vive el aprendizaje.
- **Inventó una frontera de confianza (TB5) que no pedí y que es discutible** —
  separar "servicio de autenticación" del resto sugiere una arquitectura de
  componentes que DVWA no tiene (es un `login.php` en el mismo proceso).

### Conclusión

El LLM es una **lista de verificación breadth-first que hay que verificar**, no un
sustituto de conocer mis propias fronteras. Ganó en cobertura (me recuperó CSRF y
LFI), perdió en precisión (recomendaciones de una app que no es la mía) y en rigor
(cero garantías condicionales). El patrón encaja con el debrief de la semana: se
estudian los fallos de la IA, no solo sus aciertos.

---

## Dónde pude haber sido injusto, y qué no probé

- El corpus de textos ingleses son 12 claves sobre **un solo plaintext**; no
  medí el ataque sobre variedad de estilos de prosa.
- El pase solo-frecuencias rindió 31 % aquí, por debajo del 50–70 % que anticipa
  el enunciado — probablemente porque este pasaje concreto tiene varias letras de
  frecuencia casi idéntica; no lo verifiqué contra otros textos.
- **No implementé el bypass del eje 4** de mi propia defensa (recorte del
  encabezado zlib conocido / fuga de longitud tipo CRIME). Es la debilidad que
  más credibilidad le quitaría a la garantía.
- No medí falsos positivos de la defensa sobre "tráfico benigno" real (mensajes
  cortos, con acentos, con dígitos) — solo sobre un mensaje de ejemplo.
- **Tarea 2:** modelé DVWA "desde afuera" en nivel `low` y con la configuración de
  Docker por defecto; no verifiqué el despliegue real (usuario del contenedor,
  socket de Docker, versión de PHP). Toda la columna de evidencia es "no probado
  aún" — el ataque real es la semana 6.
- **Tarea 3:** usé un solo LLM (Claude) con un solo prompt y le di solo mi
  párrafo de descripción, no el diagrama; otro modelo, o darle más contexto,
  podría cambiar qué recupera y qué inventa, y no puedo saberlo sin ejecutarlo.
  La comparación es sobre *esa* salida, no sobre "los LLM" en general.

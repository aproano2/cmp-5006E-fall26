# CMP-5006E — flujo de trabajo semanal

Repo del curso. Cada semana trae material nuevo del profesor y un studio que hay
que resolver y entregar. Este archivo describe cómo se hace, para no re-derivarlo
cada semana.

## Remotos y ramas

| Remoto | URL | Para qué |
|---|---|---|
| `origin` | `github.com/aproano2/cmp-5006E-fall26` | upstream del profesor — **solo pull** |
| `myfork` | `github.com/martin2000002/cmp-5006E-fall26` | fork personal — aquí se pushea |

Una rama por semana: **`week-NN-00328595`** (`00328595` = código de estudiante).
Se crea desde `main` actualizado, nunca desde la rama de la semana anterior.

```bash
git fetch origin
git checkout main && git merge --ff-only origin/main
git checkout -b week-03-00328595
```

Al terminar: `git push -u myfork week-03-00328595`. Los compañeros clonan el fork
y hacen checkout de esa rama.

## Orden de lectura (siempre el mismo)

1. `slides/week-NN/deck.md` — de qué va la clase y cuál es la tesis de la semana.
2. `studios/week-NN/README.md` — las tasks, los entregables y el presupuesto de tiempo.
3. `resources/control-scorecard.md` — la rúbrica. **Se usa todas las semanas**, la
   última task del studio siempre es llenarla.
4. Los archivos `.py` del studio: los marcados "GIVEN / do not modify" se leen pero
   no se tocan; solo se edita `starter.py`.

## Qué se entrega

- **`starter.py`** con las funciones implementadas. Los archivos `GIVEN` no se modifican.
- **Todos los tests provistos pasando** (`python3 test_<algo>.py`). Algunos tests
  esperan que una garantía *falle* — eso es intencional, no es un bug.
- **`WRITEUP.md`** en la carpeta del studio: responde las preguntas de cada task y
  contiene el Control Scorecard **en el formato y el tamaño que pida ese README**.
- Los **bonus del README** (renders, demos) si los pide.

## El Control Scorecard

**El README del studio manda sobre el alcance.** `resources/control-scorecard.md`
describe la rúbrica completa (8 ejes, evidencia con ≥20 payloads, puntuación 0–4),
pero cada semana pide una porción distinta. Si el README dice *"fill one scorecard
row for each construction (5 min)"*, es **una fila por construcción en una sola
tabla** — no una tabla de 8 ejes por construcción. Leer la instrucción literal y el
presupuesto de tiempo antes de escribir nada.

Lo que sí es constante todas las semanas:

- **Eje 2 · Garantía** — siempre como *condicional*. "AES es seguro" vale la mitad
  que "AES-CTR da confidencialidad **siempre que el par (clave, nonce) no se repita**".
- **Clasificar el fallo**: ¿rotura del primitivo o *misuse* de la construcción?
- Cerrar con **"Where we may have been unfair, and what we did not test"**. Vale nota
  real: encontrar un defecto genuino en la propia evaluación puntúa más alto que
  concluir "estamos seguros". Se califica la evaluación, no el veredicto.

## División entre 3 personas

Al terminar el studio, dar **la división de las tasks entre 3 personas**. Solo la
división: sin guion de presentación, sin repartir diapositivas, sin roles inventados.

- **Cada persona presenta un bloque entero y nadie se mete en el del otro.** Sin
  handoffs, sin que uno ponga la evidencia de la task del otro.
- Si hay 4 tasks para 3 personas, **las dos más livianas van juntas a una persona**
  (típicamente la primera y la del scorecard). No partir una task entre dos.
- Formato: una tabla `Persona | Presenta`. Nada más.

## Convenciones

- **Comentarios mínimos.** Solo para lo que no se entiende leyendo el código. Nada de
  comentar cada línea ni de escribir testamentos.
- **Writeups directos.** Responder lo que se pide, con tablas y números. Sin relleno.
- Se trabaja en inglés en el código y el writeup (el material del curso lo está).
- **Nada fuera de lo que pide el README del studio.** Sin presentaciones, sin scripts
  de evidencia y sin secciones que nadie pidió. Si el README pide una fila, es una
  fila. Las demos se presentan hablando.
- `seclab` y Docker solo aparecen en las semanas que lo indiquen; las semanas de
  cripto son Python puro con stdlib.

## Estructura del repo

```
slides/week-NN/deck.md          material de clase (Marp)
studios/week-NN/                el trabajo de la semana
notebooks/                      notebook de la sesión A
resources/control-scorecard.md  la rúbrica de todo el curso
resources/ethics-and-scope.md   límites de lo que se puede atacar
```

## Semanas hechas

| Semana | Rama | Tema |
|---|---|---|
| 01 | `week-01-00328595` | romper un cifrado clásico (análisis de frecuencias) |
| 02 | `week-02-00328595` | garantías: entropía, unicidad, one-time pad, two-time pad |
| 03 | `week-03-00328595` | modos y misuse: ECB, CTR nonce reuse, length extension, HMAC |
| 04 | `week-04-00328595` | RSA: factores compartidos (batch-GCD) y canal lateral de tiempo |

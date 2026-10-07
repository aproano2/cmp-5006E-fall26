# Week 4 — Deliverables Note (batch-GCD scaling + Control Scorecard)

## Task 2 — nota de costo: escaneo vs. tamaño del corpus

El escaneo pairwise implementado (`batch_gcd_recover`) hace un `gcd` por cada
par de claves: **O(k²)** llamadas para un corpus de tamaño `k`.

| k (tamaño del corpus) | pares GCD (k·(k-1)/2) |
|---|---|
| 8 (este lab) | 28 |
| 100 | 4,950 |
| 1,000 | 499,500 |
| 10,000 | 49,995,000 |

Para k = 8 esto es instantáneo (28 GCDs). Pero el escaneo real de Heninger et
al. (2012) cubrió **millones** de claves TLS/SSH — a esa escala, O(k²) pares
sería computacionalmente inviable (billones de operaciones).

**En una frase:** el escaneo a escala de internet siguió siendo barato porque
usaron un **product/remainder tree** (construir el producto de todos los `n`,
luego reducir cada `n_i` módulo ese producto) para obtener el GCD de cada clave
contra *todas las demás a la vez*, bajando el costo de O(k²) a **casi
lineal (O(k log k))** — no porque cada GCD individual sea más rápido, sino
porque evita repetir el trabajo par por par.

---

## Task 4 — Control Scorecard

| Control | Guarantía (eje 2) | Su condición (lo que el algoritmo NO puede imponer) |
|---|---|---|
| **RSA-2048** | Infactible factorizar `n`. | `p` y `q` deben venir de **buena entropía** y ser elegidas **independientemente**. Evidencia (Task 2): con RNG débil, dos claves de un corpus de 8 compartieron un primo — `gcd(n_i, n_j)` reveló el factor **instantáneamente**, sin factorizar nada, y ambas claves cayeron. Cada clave era "segura" **de forma aislada**; la garantía colapsó **a nivel de población**. Este fue el hallazgo real de Heninger et al. (2012) sobre ~0.2% de las claves TLS en producción. |
| **Cualquier comparación de secretos** | Que el resultado (verdadero/falso) sea la única información que se filtra. | Debe ejecutarse en **tiempo constante**, o filtra. Evidencia (Task 3): `insecure_equal` sale en el primer byte que no coincide, así que la **duración** revela cuántos bytes del prefijo coincidieron. El ataque de timing (interleaving de 256 candidatos por posición, 41 rondas, mediana) recuperó el secreto completo (`a53c`) sin leerlo jamás — solo cronometrando. `constant_time_equal` (que examina **todos** los bytes siempre, sin salida anticipada) fue sometido exactamente al mismo ataque y **no filtró nada** (recuperó `0000` ≠ secreto real). El algoritmo de comparación no cambió su propósito — cambió la *condición* (tiempo constante), y eso bastó para cerrar el canal. |

### Nota sobre el número de rondas (timing attack)

Usé `rounds=41` (el valor por defecto sugerido por el lab, heredado del
notebook). Con interleaving de las 256 candidatas por posición, 41 rondas dieron
una señal estable de forma consistente — el delta esperado es de solo **un
`AMPLIFY` loop extra** (~12000 iteraciones) por byte correcto, así que sin
interleaving (o con muy pocas rondas) el jitter de CPU/scheduler puede fácilmente
enmascarar esa diferencia. Con 41 rondas el ataque recuperó el secreto de 2 bytes
de forma reproducible en ambas corridas (~1 s en total, como advierte el README).

---

## Conclusión: ¿ruptura del primitivo o mal uso de la condición?

**Ninguno de los dos ataques rompió RSA como primitivo matemático.** En los dos
casos, la factorización de un módulo *fuerte* nunca ocurrió:

- El batch-GCD no factorizó nada — usó una debilidad de **generación de claves**
  (mala entropía → primos compartidos) que hace la factorización *trivial* por
  aritmética elemental (un `gcd`), sin tocar la dureza de la factorización en sí.
- El ataque de timing no rompió ninguna primitiva criptográfica — explotó una
  **implementación variable-en-tiempo** de una comparación, una condición
  totalmente externa al algoritmo que se estaba "protegiendo".

Ambos confirman el patrón central de la semana: **la garantía del algoritmo es
condicional a cosas que el algoritmo mismo no puede imponer.** Los atacantes
rompen las condiciones, no las matemáticas.

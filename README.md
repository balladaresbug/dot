DOT: cifrado por bloques en Python
=================================

Este módulo implementa **DOT**, un cifrado por bloques de 256 bits escrito en
Python puro y un conjunto de modos de operación modernos (ECB, CBC, CTR y
GCM). Incluye derivación de claves, manejo de IV/nonce y utilidades para
cifrar y descifrar archivos sin dependencias externas.


Características principales
---------------------------
- Implementación completa en Python: ideal para entornos donde no se permite
  código nativo.
- Tamaño de bloque de 256 bits (32 bytes) y 36 rondas por defecto.
- S-Boxes dinámicas derivadas de la clave maestra para endurecer la difusión.
- Modos de operación con padding PKCS#7 para ECB/CBC, stream seguro en CTR y
  autenticación integrada en GCM (etiquetas de 16 bytes).
- Derivación de claves segura mediante PBKDF2-HMAC-SHA512 y generación de
  entropía usando `secrets`.
- API de alto nivel para trabajar con datos en memoria o archivos.


Arquitectura del módulo
-----------------------
- `src/dot/core.py`: contiene `DotCipher`, el cifrado por bloques de 32 bytes
  con 36 rondas de: aplicación del S-Box, permutación de bytes (shift rows),
  mezclas aditivas/rotacionales y suma de subclaves por ronda.
- `src/dot/sbox.py`: construye S-Boxes dinámicas con `SHA3-512` y `BLAKE2b` a
  partir de la clave. También genera la tabla inversa para descifrado.
- `src/dot/keyschedule.py`: expande la clave maestra (32 bytes) en subclaves
  por ronda y constantes de rotación usando `BLAKE2b` + `SHA3-256` como PRNG.
- `src/dot/modes.py`: implementa los modos de operación:
  - **ECB** y **CBC**: padding PKCS#7 de 32 bytes; CBC requiere IV aleatorio
    del tamaño del bloque.
  - **CTR**: nonce de 12 bytes + contador de 32 bits; el nonce se antepone al
    ciphertext si no se fija manualmente.
  - **GCM**: nonce de 12 bytes, etiqueta de 16 bytes y GHASH sobre AAD y
    ciphertext; el contador inicia en 2 para evitar reutilizar el bloque J0.
- `src/dot/kdf.py`: deriva claves con PBKDF2-HMAC-SHA512 (salt de 16 bytes,
  310k iteraciones) o genera claves aleatorias de 32 bytes.
- `src/dot/api.py`: expone `DotEncrypter`, una interfaz de alto nivel que
  configura el modo, gestiona IV/nonce, empaqueta resultados (`DotEncryptionResult`)
  y permite cifrar/descifrar archivos con un formato autocontenible.
- `src/dot/__init__.py`: facilita las importaciones públicas del paquete.


Requisitos de tamaño y entradas
-------------------------------
- **Clave maestra**: exactamente 32 bytes (`DotCipher` se inicializa con ese
  tamaño). `DotKeyDerivation.generate_key()` produce una clave válida.
- **Bloque**: 32 bytes (256 bits).
- **IV/nonce**:
  - CBC: 32 bytes (igual al tamaño de bloque).
  - CTR: 12 bytes (se antepone al ciphertext si no se proporciona manualmente).
  - GCM: 12 bytes (generado aleatoriamente en cada cifrado).
- **Etiqueta GCM**: 16 bytes.


Uso rápido
----------
Derivar una clave desde una contraseña y cifrar/descifrar en memoria:

```python
from dot import DotEncrypter

encrypter = DotEncrypter.from_password("mi-contraseña-segura", mode="CBC")
resultado = encrypter.encrypt(b"mensaje secreto")
texto_plano = encrypter.decrypt(resultado)
```

Cifrado autenticado con datos asociados (AAD) en GCM:

```python
from dot import DotEncrypter

encrypter = DotEncrypter(mode="GCM")
aad = b"cabecera/autenticada"
resultado = encrypter.encrypt(b"mensaje", aad=aad)
texto_plano = encrypter.decrypt(resultado, aad=aad)
```

Cifrar y descifrar archivos (el formato guarda modo, IV/nonce y tag cuando
aplica):

```python
from dot import DotEncrypter

encrypter = DotEncrypter(mode="CTR")
encrypter.encrypt_file("entrada.bin", "salida.dot")
encrypter.decrypt_file("salida.dot", "restaurado.bin")
```


Formato de archivos cifrados
----------------------------
`DotEncrypter.encrypt_file` escribe un encabezado mínimo antes del ciphertext:

1. 1 byte: longitud del nombre del modo.
2. Nombre del modo en ASCII (p. ej., `"GCM"`).
3. 2 bytes big-endian: longitud de IV/nonce, seguido de los bytes (0 si no
   aplica, como en ECB).
4. 2 bytes big-endian: longitud de la etiqueta, seguido de los bytes (0 si no
   aplica).
5. Resto del archivo: ciphertext.

Con este encabezado `decrypt_file` puede reconstruir la configuración necesaria
para descifrar sin parámetros externos.


Buenas prácticas de seguridad
-----------------------------
- Use una clave distinta por aplicación o usuario y protéjala en repositorios
  seguros; evite hardcodearla en el código fuente.
- Nunca reutilice nonces de 12 bytes en CTR o GCM para la misma clave; el
  encriptador genera nonces aleatorios para minimizar el riesgo.
- Asegúrese de validar la etiqueta en GCM (ya se hace en `DotModeOfOperationGCM`)
  y maneje las excepciones de verificación para evitar ataques de replay o
  manipulación.
- Prefiera GCM para confidencialidad + integridad; utilice CTR/CBC solo cuando
  la autenticación se gestione en otra capa.


Pruebas rápidas
---------------
Para verificar la importación y compilación del paquete:

```bash
python -m compileall -q src
```

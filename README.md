# fileEncripter
Proyecto final del curso de ciberseguridad de la Universidad Icesi, el cual implementa un cifrador/descifrador de archivos. El programa funciona de la
siguiente manera:

1. Para cifrar, el programa recibe como entrada un archivo cualquiera, y una contraseña. A partir de la contraseña, se genera una clave de 128 bits, 
empleando el algoritmo PBKDF2. El archivo se cifra con el algoritmo AES, usando la clave obtenida; el resultado se escribe a otro archivo, que contiene 
también el hash SHA-256 del archivo sin cifrar.

2. Para descifrar, el programa recibe como entrada un archivo cifrado y la contraseña. El programa descifra el archivo y escribe el resultado en un 
archivo nuevo. Luego, computa el hash SHA-1 del archivo descifrado y lo compara con el hash almacenado con el archivo cifrado.

### Tecnologías usadas
- Java 17.2
- JavaFX 17.2
- Eclipse IDE

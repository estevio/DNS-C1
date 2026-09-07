# DNS-C1

## Requisitos

- Python
- Tener la librería dnslib instalada.

## Cómo ejecutar

Actualizar las variables IP_VM y debug dependiéndo del comportamiento esperado. Luego, en la carpeta DNS-C1, ingresar el comando:

```bash
python3 resolver.py
```

## Cómo probar

En otra terminal ejecutar el siguiente comando:

```bash
dig -p8000 @[IP_VM] [nombre_de_dominio]
```

# redos\_detector

Herramienta en Python para detectar y validar dinámicamente patrones de expresiones regulares potencialmente vulnerables a ReDoS (Regular Expression Denial of Service) en un código fuente.

## Descripción

`redos_detector.py` recorre recursivamente un directorio de proyecto, busca literales de regex (incluyendo llamadas a `new RegExp(...)`), detecta cuantificadores anidados (p. ej. `(a+)+`, `(.+)?`), y luego ejecuta una prueba dinámica contra una “carga maliciosa” para medir tiempo de backtracking. Solo reporta patrones cuya validación supera un umbral configurable (por defecto 100 ms), indicando ruta, línea, patrón y duración de la prueba.

## Características

- Soporta archivos JavaScript/TypeScript (`.js`, `.jsx`, `.ts`), Python (`.py`) y Java (`.java`).
- Omite silenciosamente archivos inaccesibles.
- Detección estática + validación dinámica automática.
- Umbral de tiempo configurable mediante constante en el código.

## Requisitos

- Python 3.6 o superior.
- No requiere librerías externas (solo `re`, `os`, `argparse`, `time`).

## Instalación

1. Clona o descarga este repositorio:
   ```bash
   git clone https://github.com/tu-usuario/redos-detector.git
   cd redos-detector
   ```
2. Asegúrate de tener Python 3 instalado:
   ```bash
   python --version
   ```

## Uso

```bash
python redos_detector.py [ruta]
```

- **ruta**: Directorio a escanear. Si se omite, escanea el directorio actual.

### Ejemplo

```bash
python redos_detector.py /home/usuario/proyecto
```

Salida:

```
/home/usuario/proyecto/app/controllers/data.js:45    (.+)?angular(\\|\/)core(.+)?    2492.8ms
/home/usuario/proyecto/app/controllers/number.js:12  ^-?\d+(?:\.\d+)?$              2122.1ms
```

Cada línea muestra:

- Ruta del archivo y línea donde se detectó el patrón.
- Expresión regular vulnerable.
- Tiempo en milisegundos que tardó la prueba dinámica.

## Personalización

- **Threshold**: Puedes cambiar el umbral de 100 ms modificando el valor en la función `is_vulnerable()`.
- **Extensiones**: Para ampliar o restringir tipos de archivo, edita la tupla en `scan_directory()`.

## Contribuyendo

1. Haz un *fork* del repositorio.
2. Crea una rama con tu mejora (`git checkout -b feature/nueva-funcion`).
3. Realiza tus cambios y haz *commit*.
4. Envía un *pull request* describiendo tu aportación.

## Licencia

Este proyecto está licenciado bajo [MIT License](LICENSE).


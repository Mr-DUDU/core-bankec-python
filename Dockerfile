# Usar imagen base de Python 3.10-slim
FROM python:3.10-slim

# Crear un grupo y usuario no privilegiado
RUN addgroup --system nonroot && adduser --system --ingroup nonroot nonroot

# Establecer el directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema (gcc, libpq-dev para compilar psycopg2)
RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# Copiar archivo de requerimientos e instalar dependencias Python
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY app/ ./app/

# Cambiar la propiedad del directorio /app para que el usuario noroot tenga acceso de escritura
RUN chown -R nonroot:nonroot /app

# Exponer el puerto 8000
EXPOSE 8000

# Cambiar a usuario no privilegiado
USER nonroot

# Ejecutar la aplicación con Gunicorn (4 workers)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app.main:app"]
# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . .

# Make port 5000 available to the world outside this container
EXPOSE 20242

# Define environment variable for Flask
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Run the Flask application
#CMD ["flask", "run", "--host=0.0.0.0"]
# Run Gunicorn WSGI server
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:20242", "app:app"]
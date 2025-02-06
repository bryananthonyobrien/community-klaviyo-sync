# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the application files into the container
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 5000 for Flask
EXPOSE 5000

# Run the Flask app with Gunicorn (for better performance)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]


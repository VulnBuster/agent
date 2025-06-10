FROM python:3.11-slim-buster

WORKDIR /app

COPY main.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Install Node.js and npm
RUN apt-get update && apt-get install -y nodejs npm

# Install npx
RUN npm install -g npx

# Set GRADIO_TEMP_DIR
ENV GRADIO_TEMP_DIR=/app/temp
RUN mkdir /app/temp

EXPOSE 7860
ENV GRADIO_SERVER_NAME="0.0.0.0"

CMD ["python", "main.py"]

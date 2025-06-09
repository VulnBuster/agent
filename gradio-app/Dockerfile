FROM python:3.11-slim-buster

WORKDIR /app

COPY app.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Install Node.js 18 and npm
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
RUN apt-get install -y nodejs

# Install mcp-remote (npx уже включен в современный Node.js)
RUN npm install -g mcp-remote

# Set GRADIO_TEMP_DIR
ENV GRADIO_TEMP_DIR=/app/temp
RUN mkdir /app/temp

EXPOSE 7860
ENV GRADIO_SERVER_NAME="0.0.0.0"

CMD ["python", "app.py"]

FROM python:3.11-slim-buster

WORKDIR /app

COPY app.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 7860

CMD ["python", "app.py"]

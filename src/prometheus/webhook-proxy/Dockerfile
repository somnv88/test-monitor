FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY webhook_proxy.py .

EXPOSE 5000

CMD ["python", "webhook_proxy.py"]
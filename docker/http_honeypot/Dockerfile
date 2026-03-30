FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.0

COPY app.py .
RUN mkdir -p /app/logs

EXPOSE 8080

ENV FLASK_ENV=production

CMD ["python", "app.py"]

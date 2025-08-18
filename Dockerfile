# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY frontend-fauth-demo/requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY frontend-fauth-demo/app /app/app
COPY frontend-fauth-demo/fusion_auth_client /app/fusion_auth_client

ENV FLASK_APP=app/main.py \
    PORT=5000

EXPOSE 5000

CMD ["python", "-m", "app.main"]



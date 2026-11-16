FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 collector

COPY --chown=collector:collector sync_wiz.py .
USER collector

CMD ["python", "-u", "sync_wiz.py"]

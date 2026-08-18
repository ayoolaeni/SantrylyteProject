FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p instance instance/spill

EXPOSE 5000
EXPOSE 5514/udp
EXPOSE 5514/tcp

ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1

CMD ["python", "run.py"]

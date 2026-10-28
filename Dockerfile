FROM python:3.11-slim

WORKDIR /app

# Every dependency ships as a pre-built wheel for both amd64 (Windows/Intel Macs) and
# arm64 (Apple Silicon Macs), psycopg included via psycopg[binary], so no compiler or
# system packages are needed. Skipping apt-get keeps the first start fast and avoids
# depending on the Debian mirrors being reachable from the client's network.
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

# Edge device image - built for linux/arm64 (Raspberry Pi 4/5 class MPU) by docker-compose
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
# keys/ and state/ are mounted as volumes, never baked into the image
CMD ["python", "edge_client.py"]

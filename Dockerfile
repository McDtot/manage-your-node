FROM python:3.12-slim

WORKDIR /app

ENV APP_DATA_DIR=/data
ENV HOST=0.0.0.0
ENV PORT=8787

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8787

CMD ["python", "-m", "app.server"]

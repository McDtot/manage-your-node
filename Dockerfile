FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

WORKDIR /app

ENV APP_DATA_DIR=/data
ENV HOST=0.0.0.0
ENV PORT=8787

RUN groupadd --gid 10001 manage-node \
    && useradd --uid 10001 --gid manage-node --home-dir /app --no-create-home manage-node \
    && install -d -o manage-node -g manage-node -m 0700 /data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=manage-node:manage-node app ./app

USER manage-node:manage-node

EXPOSE 8787

CMD ["python", "-m", "app.server"]

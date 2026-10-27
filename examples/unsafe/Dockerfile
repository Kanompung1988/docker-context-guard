FROM python:3.12-slim
ARG NPM_TOKEN
ENV APP_PASSWORD=placeholder-not-a-real-secret
WORKDIR /app
COPY . .
RUN python -m compileall -q .

FROM nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
USER 10001

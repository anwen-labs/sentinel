# No USER instruction -> runs as root by default.
# EXPECT: Medium DOCKERFILE-ROOT-USER
FROM ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN echo build
COPY app /app

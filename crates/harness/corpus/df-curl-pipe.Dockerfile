# EXPECT: High DOCKERFILE-CURL-PIPE-EXECUTION
FROM ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
USER 10001
RUN curl -sSL https://example.com/install.sh | sh

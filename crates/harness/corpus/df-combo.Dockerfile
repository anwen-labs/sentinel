# Multiple Dockerfile issues. Full ground-truth label set.
# EXPECT: High DOCKERFILE-CURL-PIPE-EXECUTION
# EXPECT: Medium DOCKERFILE-ADD-REMOTE-URL
# EXPECT: Medium DOCKERFILE-BUILD-SECRET
# EXPECT: Medium DOCKERFILE-ROOT-USER
# EXPECT: Low DOCKERFILE-BASE-IMAGE-UNPINNED
# EXPECT: Low DOCKERFILE-SUDO
FROM ubuntu:latest
RUN curl -sSL https://get.example.com/install.sh | bash
ADD https://example.com/app.tar.gz /app/
ENV API_KEY=sk-live-secret123
RUN sudo apt-get update && apt-get install -y nginx
COPY . /app

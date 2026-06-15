# EXPECT: High DOCKERFILE-CURL-PIPE-EXECUTION
FROM nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN wget -qO- https://get.example.com/install.sh | bash
USER 10001

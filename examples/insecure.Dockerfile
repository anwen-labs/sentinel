FROM ubuntu:latest

RUN curl -sSL https://get.example.com/install.sh | bash
ADD https://example.com/app.tar.gz /app/
ENV API_KEY=sk-live-secret123
RUN sudo apt-get update && apt-get install -y nginx

COPY . /app
CMD ["/app/run.sh"]

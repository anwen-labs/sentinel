# Hardened: pinned base, non-root user, no risky instructions. Expect zero findings.
FROM ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
COPY app /app
USER 10001
CMD ["/app/run"]

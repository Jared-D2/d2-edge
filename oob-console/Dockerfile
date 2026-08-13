# debian, not alpine: alpine 3.20 ships ser2net 3.5.1 whose line-based
# parser cannot read the YAML config at all (pilot-caught — it logged
# "No state given" per line and bound nothing). trixie ships ser2net 4.x.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ser2net \
    && rm -rf /var/lib/apt/lists/* \
    && ser2net -v
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

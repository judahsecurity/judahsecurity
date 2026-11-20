# Explorer sandbox egress proxy: scope enforcement and exchange recording.
# Build context: backend/sandbox
FROM mitmproxy/mitmproxy:11.0.2
USER root
RUN pip install --no-cache-dir redis==5.0.8 && mkdir -p /ca-public && chown mitmproxy /ca-public
COPY egress/addon.py egress/policy.py egress/entrypoint.sh /opt/prowl-egress/
RUN chmod 0555 /opt/prowl-egress/entrypoint.sh
ENV PYTHONPATH=/opt/prowl-egress
USER mitmproxy
EXPOSE 8080
ENTRYPOINT ["/opt/prowl-egress/entrypoint.sh"]

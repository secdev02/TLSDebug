FROM mitmproxy/mitmproxy:latest

USER root

COPY entrypoint.sh /home/mitmproxy/entrypoint.sh
COPY addon.py /home/mitmproxy/addon.py
RUN chmod +x /home/mitmproxy/entrypoint.sh

USER mitmproxy

EXPOSE 8080
EXPOSE 8081

ENTRYPOINT ["/home/mitmproxy/entrypoint.sh"]

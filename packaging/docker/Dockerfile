# Imagem do HeimdallDNS (montada pelo goreleaser, que coloca o binário de
# cada plataforma em $TARGETPLATFORM/). Sem shell, sem root.
FROM busybox:1.37 AS prep
RUN mkdir -p /data && chown 65532:65532 /data

FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/heimdalldns /usr/bin/heimdalldns
COPY packaging/docker/heimdalldns.yaml /etc/heimdalldns/heimdalldns.yaml
COPY LICENSE THIRD_PARTY_LICENSES.md /usr/share/licenses/heimdalldns/
COPY --from=prep --chown=65532:65532 /data /data
VOLUME /data
# O Docker já libera portas baixas para usuário comum dentro do contêiner
# (net.ipv4.ip_unprivileged_port_start=0).
EXPOSE 53/udp 53/tcp 8053/tcp
ENTRYPOINT ["/usr/bin/heimdalldns", "-config", "/etc/heimdalldns/heimdalldns.yaml"]

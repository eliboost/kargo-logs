FROM linux-docker-local.repo.pnet.ch/pf/alpine:3.24.2202610140623

ARG TARGETARCH
ARG TARGETOS
ARG http_proxy=http://outapplpf.pnet.ch:3128
ARG https_proxy=http://outapplpf.pnet.ch:3128
ARG no_proxy=localhost,127.0.0.1,.pnet.ch
ARG TZ=Europe/Zurich

ENV TZ=${TZ}

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/kargo-analysisrun-logs /usr/bin/kargo-analysisrun-logs
COPY packaging/docker/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

# renovate: datasource=gitlab-tags depName=middleware/argocd/k8s-compauth-authenticator
ARG K8S_COMPAUTH_AUTHENTICATOR_VERSION="0.2.2"
ADD --chmod=744 --chown=65534 https://middleware-generic.repo.pnet.ch/artifactory/middleware-generic-local/pf/k8s-compauth-authenticator/k8s-compauth-authenticator_linux_amd64-${K8S_COMPAUTH_AUTHENTICATOR_VERSION} /opt/compauth-auth


USER 65534

ENTRYPOINT ["/entrypoint.sh"]


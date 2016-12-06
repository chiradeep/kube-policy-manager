FROM golang:1.7-alpine
RUN apk add --no-cache iptables
COPY kube-policy-manager /usr/local/bin/

ENTRYPOINT ["kube-policy-manager"]

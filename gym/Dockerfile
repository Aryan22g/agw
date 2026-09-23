# One image for all three roles. They differ only in the command they run,
# which keeps the containers identical in everything that is not the point.
FROM alpine:3.21

RUN apk add --no-cache ca-certificates curl && adduser -D -u 10001 gym

COPY bin/agw     /bin/agw
COPY bin/ags     /bin/ags
COPY bin/agw-gym /bin/agw-gym
COPY conf        /conf

RUN chmod 0755 /bin/agw /bin/ags /bin/agw-gym

# Deliberately root. The threat model is an agent that has root inside its own
# sandbox and does not want to cooperate; dropping privileges here would test a
# weaker adversary than the one this exists for.
USER root

ENTRYPOINT []

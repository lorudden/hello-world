FROM --platform=$BUILDPLATFORM docker.io/golang:1.24 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

RUN go install github.com/a-h/templ/cmd/templ@latest

ARG TARGETARCH
ARG TARGETOS

RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-$TARGETOS-$TARGETARCH
RUN chmod +x tailwindcss-$TARGETOS-$TARGETARCH
RUN mv tailwindcss-$TARGETOS-$TARGETARCH tailwindcss

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN templ generate
RUN ./tailwindcss -c ./css/tailwind.config.js -i ./css/input.css -o ./css/output.css

WORKDIR /app/cmd/hello-world

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build


FROM registry.access.redhat.com/ubi9/ubi-minimal
WORKDIR /opt/lorudden

COPY --from=builder --chown=1001 /app/cmd/hello-world/hello-world /opt/lorudden
COPY --from=builder --chown=1001 /app/css/output.css /opt/lorudden/css/output.css
COPY --from=builder --chown=1001 /app/js/htmx.min.js /opt/lorudden/js/htmx.min.js

RUN chown 1001 /opt/lorudden

EXPOSE 8080
USER 1001

ENTRYPOINT ["/opt/lorudden/hello-world"]

# Default image: pure-Go static binary, no OCR. Small and dependency-free.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/egress-scan .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/egress-scan /usr/local/bin/egress-scan
ENTRYPOINT ["/usr/local/bin/egress-scan"]

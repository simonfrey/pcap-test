#
# Builder
#

FROM golang:1.18.10-bullseye AS builder

# Create a workspace for the app
WORKDIR /app

# Copy over the files
COPY . ./

RUN apt-get update
RUN apt-get install -y libpcap-dev gcc

# Build
RUN go build -o pcap-test
RUN ls


ENTRYPOINT ["/app/pcap-test"]


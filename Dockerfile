# Use golang:alpine as the base image
FROM golang:alpine

# Install required dependencies (libpcap, gcc, and musl-dev)
RUN apk add --no-cache gcc musl-dev libpcap-dev

# Set the working directory
WORKDIR /app
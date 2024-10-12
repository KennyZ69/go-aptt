
# Use an official Golang image as the base image
FROM golang:1.22.7-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and download dependencies
# COPY ./ /app
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . /app

# Build the Go application
RUN go build -o security-scanner .

# Command to run your security scanner on the codebase
CMD ["./security-scanner", "--codebase", ".", "--attack"]

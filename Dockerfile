
# Use an official Golang image as the base image
FROM golang:1.22.7-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build the Go application
RUN go build -o security-scanner .

# Command to run your security scanner on the codebase
CMD ["./security-scanner", "."]

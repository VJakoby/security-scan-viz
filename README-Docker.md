# Vulnerability Dashboard - Docker Setup

## Quick Start

### Option 1: Using Docker Compose (Recommended)
```bash
# Build and run the container
docker-compose up --build

# Access the application at http://localhost:8888
```

### Option 2: Using Docker directly
```bash
# Build the image
docker build -t vulnerability-dashboard .

# Run the container
docker run -p 8888:8888 vulnerability-dashboard

# Access the application at http://localhost:8888
```

## Development

To rebuild after making changes:
```bash
docker-compose down
docker-compose up --build
```

## Stopping the Application
```bash
# Using docker-compose
docker-compose down

# Using docker directly
docker stop vulnerability-dashboard
```

## Features
- ✅ Complete vulnerability dashboard in a Docker container
- ✅ CSV file upload and analysis
- ✅ Interactive charts and tables
- ✅ Standalone HTML export
- ✅ Responsive design
- ✅ Easy deployment with Docker

Access your dashboard at: **http://localhost:8888**
# SC-DOJO — SecureChain ↔ DefectDojo Integration

## Overview

SC-DOJO is a backend and frontend integration layer between SecureChain and DefectDojo.

The project allows:

- Generation of Generic Findings documents
- Correlation of SBOM, VEX and TIX documents
- Export of vulnerabilities into DefectDojo
- Visualization and management from SecureChain frontend
- Centralized vulnerability workflow management

---

## Requirements

- **Docker Engine 20.10+**: Container runtime for running all services
- **Docker Compose V2**: Required for orchestrating multi-container applications
- **make utility**: Used to run build and deployment commands from the makefile
- **zstd**: Compression tool needed to extract database dumps from Zenodo
- **git**: Used for managing different github repositories.
System Resources:
Minimum 4GB RAM (Neo4j and MongoDB require memory for optimal performance)
At least 10GB free disk space for images, containers, and database data

Check installation:

```bash
docker --version
docker compose version
git --version
```

---

## Repository Structure

Recommended workspace:

```text
securechain-stack/
├── securechain/
├── securechain-defectdojo-integration/
└── django-DefectDojo/
```

---

## 1. Install SecureChain

Before starting with the installation it is recomended to clone the repository [SecureChain-stack](https://github.com/securechaindev/securechain-stack) in the securechain directory for easier installation

```bash
git clone https://github.com/securechaindev/securechain-stack
```

### 1. Create Docker network

SecureChain requires a shared Docker network:

```bash
docker network create securechain
```

### 2. Configure environment variables

Create a `.env` file using `make generate-env` command, and fill it in with your information where necessary.

#### Get API Keys

- How to get a *GitHub* [API key](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens).

- Modify the **Json Web Token (JWT)** secret key and algorithm with your own. You can generate your own secret key with the command **openssl rand -base64 32**.

**Security Note**: Always change default credentials before deploying to production environments.

Generate configuration files:
```bash
make generate-env                    # Uses stable profile (default)
make generate-env PROFILE=latest     # Uses latest profile
```

The `generate-env` script only creates files if they don't exist, preserving any manual changes you've made.

### 3. Download database dumps from Zenodo (optional but recommended)

Downloads and extracts Neo4j and MongoDB [seed data](https://doi.org/10.5281/zenodo.16739080) from **Zenodo** with `make download-dump` command. This step is optional because it does not affect the correct deployment of the tools, but if you want to use the extracted graph data for your software supply chain analysis, it is a recommended step. It should also be noted that the dump can be large, so **a good internet connection is required**.

### 4. Modify the dockercompose.yaml

For this integration with DefectDojo, we will be using a diferent frontend from the original repository, so it is recomended to take the original docker-compose containers off the docker/docker-compose.tools.yml file. You mae leave it like this:

```yaml
services:

  securechain-gateway:
    container_name: securechain-gateway
    image: ghcr.io/securechaindev/securechain-gateway:latest
    env_file: ../.env
    ports:
      - '8000:8000'
    networks:
      - securechain
    depends_on:
      securechain-auth:
        condition: service_healthy
      securechain-depex:
        condition: service_healthy
      securechain-vexgen:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 5s
      timeout: 3s
      retries: 5

  securechain-auth:
    container_name: securechain-auth
    image: ghcr.io/securechaindev/securechain-auth:latest
    env_file: ../.env
    ports:
      - '8000'
    networks:
      - securechain
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 5s
      timeout: 3s
      retries: 5

  securechain-depex:
    container_name: securechain-depex
    image: ghcr.io/securechaindev/securechain-depex:latest
    env_file: ../.env
    ports:
      - '8000'
    networks:
      - securechain
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 5s
      timeout: 3s
      retries: 5

  redis:
    container_name: securechain-redis
    image: redis:7-alpine
    ports:
      - '6379:6379'
    volumes:
      - redis-data:/data
    networks:
      - securechain
    command: redis-server --appendonly yes

  securechain-vexgen:
    container_name: securechain-vexgen
    image: ghcr.io/securechaindev/securechain-vexgen:latest
    env_file: ../.env
    ports:
      - '8000'
    networks:
      - securechain
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 5s
      timeout: 3s
      retries: 5

networks:
  securechain:
    name: securechain
    external: true
    driver: bridge

volumes:
  redis-data:
```
### 5. Start services

Use the  `make up MODE=all` for deploying every container from the securechain stack except the secure-frontend container that will be installed afterwards. 

---

#### Validate deployment

```bash
docker ps
```

Expected containers:

```text
securechain-gateway
securechain-vexgen
securechain-auth
securechain-depex
mongo
neo4j
redis
```

---

#### Access SecureChain

Frontend:

```text
http://localhost
```

Neo4j:

```text
http://localhost:7474
```

---

## 2. Install DefectDojo

### 1.Clone repository:

```bash
cd ~/securechain-stack

git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo
```

### 2.Start DefectDojo

```bash
docker compose up -d
```

Wait several minutes until initialization finishes.

### 3.Obtain admin credentials

```bash
docker compose logs initializer | grep "Admin password:"
```

### 4.Access DefectDojo

```text
http://localhost:8080
```

Default user:

```text
admin
```

Password appears in initializer logs.

### 5. Create Product and Engagement

Inside DefectDojo:

### Create Product

```text
Products → Add Product
```

### Create Engagement

Inside the created product:

```text
Add Engagement
```

### 6. Generate DefectDojo API Key

In DefectDojo:

```text
User → API v2 Key
```

Save the generated token.

---

## 3 Install SC-DOJO Backend

### 1.Clone repository:

```bash
git clone <SC_DOJO_BACKEND_REPOSITORY_URL> securechain-defectdojo-integration
cd securechain-defectdojo-integration
```

### 2.Configure Backend Environment

Create `.env`:

```bash
nano .env
```

#### Example `.env`

```env
# =========================
# MongoDB
# =========================
MONGODB_URI=mongodb://mongoSecureChain:mongoSecureChain@mongo:27017/?authSource=admin
MONGODB_DB_NAME=securechain
MONGODB_GENERIC_FINDINGS_COLLECTION=generic_findings

# =========================
# VEXGEN
# =========================
VEXGEN_BASE_URL=http://securechain-vexgen:8000
VEXGEN_GENERATE_PATH=/vex_tix/generate
VEXGEN_API_KEY=YOUR_VEXGEN_API_KEY

# =========================
# DefectDojo
# =========================
DEFECTDOJO_ENABLED=true
DEFECTDOJO_BASE_URL=http://django-defectdojo-nginx-1:8080
DEFECTDOJO_API_KEY=YOUR_DEFECTDOJO_API_KEY

DEFECTDOJO_PRODUCT_NAME=SecureChain
DEFECTDOJO_ENGAGEMENT_NAME=SecureChain Generic Findings
DEFECTDOJO_TEST_TITLE=SecureChain Generic Findings
```

### 3. Start SC-DOJO Backend

```bash
docker compose -f docker-compose.dev.yml up -d --build
```

---

### 4. Validate Backend

Swagger UI:

```text
http://localhost:8001/docs
```

---

### 5. Connect Frontend to SC-DOJO

Edit SecureChain frontend Nginx configuration.

Add BEFORE generic `/api/` proxy:

```nginx
location /api/defectdojo/generic-findings/ {
    proxy_pass http://securechain-defectdojo-integration:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

#### Important

This block MUST appear before:

```nginx
location /api/ {
    proxy_pass ${BACKEND_URL};
}
```

Otherwise requests will not reach SC-DOJO.

### 4. Rebuild Frontend

```bash
cd ~/securechain-/securechain

docker compose -f dev/docker-compose.yml up -d --build
```

### 5. Validate Docker Networks

List networks:

```bash
docker network ls
```

Expected:

```text
securechain
django-defectdojo_default
```

#### Verify container connectivity

```bash
docker inspect securechain-defectdojo-integration
```

SC-DOJO must belong to BOTH networks.

---

### 5. Validate End-to-End Workflow

#### Generate Generic Findings

```bash
curl -X POST http://localhost:8001/api/defectdojo/generic-findings/generate \
-H "Content-Type: application/json" \
-d '{
  "owner":"Owner-from-loaded-repository-in-securechain",
  "repository":"repositry-name-from-loaded-repository-in-securechain"
}'
```

#### List documents

```bash
curl http://localhost:8001/api/defectdojo/generic-findings/documents
```

#### Retrieve document

```bash
curl http://localhost:8001/api/defectdojo/generic-findings/documents/<DOCUMENT_ID>
```

#### Import into DefectDojo

```bash
curl -X POST \
http://localhost:8001/api/defectdojo/generic-findings/documents/<DOCUMENT_ID>/import \
-H "Content-Type: application/json" \
-d '{
  "product_name":"SecureChain",
  "engagement_name":"SecureChain Generic Findings",
  "test_title":"SecureChain Generic Findings"
}'
```

### 6. Frontend Validation

Open:

```text
http://localhost/home
```

Validate:

- Repository listing
- Generic Findings generation
- User DefectDojo tab
- Document visualization
- Import to DefectDojo

## 5. Running Tests

Inside backend repository:

```bash
uv sync --extra test
```

Run tests:

```bash
uv run pytest -vv
```
---

# Authors
- Bruno Álvaro Rico Barrilero [Github: brico1994](https://github.com/brico1994)
SecureChain ↔ DefectDojo Integration — SC-DOJO

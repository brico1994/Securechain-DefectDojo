# SC-DOJO — SecureChain ↔ DefectDojo Integration

## Overview

SC-DOJO is a backend and frontend integration layer between SecureChain and DefectDojo.

The project allows:

- Generation of Generic Findings documents
- Correlation of SBOM, VEX and TIX artifacts
- Export of vulnerabilities into DefectDojo
- Visualization and management from SecureChain frontend
- Centralized vulnerability workflow management

---

# Requirements

You need:

- Docker
- Docker Compose
- Git
- curl

Check installation:

```bash
docker --version
docker compose version
git --version
```

---

# Repository Structure

Recommended workspace:

```text
securechain-stack/
├── securechain/
├── securechain-defectdojo-integration/
└── django-DefectDojo/
```

Create it:

```bash
mkdir -p ~/securechain-stack
cd ~/securechain-stack
```

---

# 1. Install SecureChain

Clone SecureChain:

```bash
git clone <SECURECHAIN_REPOSITORY_URL> securechain
cd securechain
git pull
```

---

## Create Docker network

SecureChain requires a shared Docker network:

```bash
docker network create securechain
```

---

## Start SecureChain

```bash
docker compose -f dev/docker-compose.yml up -d --build
```

---

## Validate deployment

```bash
docker ps
```

Expected containers:

```text
securechain-frontend
securechain-gateway
securechain-vexgen
securechain-auth
securechain-depex
mongo
neo4j
redis
```

---

## Access SecureChain

Frontend:

```text
http://localhost
```

Neo4j:

```text
http://localhost:7474
```

---

# 2. Install DefectDojo

Clone repository:

```bash
cd ~/securechain-stack

git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo
```

---

## Start DefectDojo

```bash
docker compose up -d
```

Wait several minutes until initialization finishes.

---

## Obtain admin credentials

```bash
docker compose logs initializer | grep "Admin password:"
```

---

## Access DefectDojo

```text
http://localhost:8080
```

Default user:

```text
admin
```

Password appears in initializer logs.

---

# 3. Create Product and Engagement

Inside DefectDojo:

## Create Product

```text
Products → Add Product
```

Recommended values:

```text
Name: SecureChain
Product Type: Research and Development
```

---

## Create Engagement

Inside the created product:

```text
Add Engagement
```

Recommended:

```text
Name: SecureChain Generic Findings
```

---

# 4. Generate DefectDojo API Key

In DefectDojo:

```text
User → API v2 Key
```

Save the generated token.

---

# 5. Install SC-DOJO Backend

Clone repository:

```bash
cd ~/securechain-stack

git clone <SC_DOJO_BACKEND_REPOSITORY_URL> securechain-defectdojo-integration
cd securechain-defectdojo-integration

git pull
```

---

# 6. Configure Backend Environment

Create `.env`:

```bash
nano .env
```

---

## Example `.env`

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

---

# 7. Docker Compose Configuration

Create:

```text
docker-compose.dev.yml
```

Content:

```yaml
services:
  securechain-defectdojo-integration:
    build:
      context: .
      dockerfile: Dockerfile

    container_name: securechain-defectdojo-integration

    ports:
      - "8001:8000"

    env_file:
      - .env

    networks:
      - securechain
      - defectdojo

networks:
  securechain:
    external: true
    name: securechain

  defectdojo:
    external: true
    name: django-defectdojo_default
```

---

# 8. Start SC-DOJO Backend

```bash
docker compose -f docker-compose.dev.yml up -d --build
```

---

# 9. Validate Backend

Swagger UI:

```text
http://localhost:8001/docs
```

---

# 10. Connect Frontend to SC-DOJO

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

---

## Important

This block MUST appear before:

```nginx
location /api/ {
    proxy_pass ${BACKEND_URL};
}
```

Otherwise requests will not reach SC-DOJO.

---

# 11. Rebuild Frontend

```bash
cd ~/securechain-stack/securechain

docker compose -f dev/docker-compose.yml up -d --build
```

---

# 12. Validate Docker Networks

List networks:

```bash
docker network ls
```

Expected:

```text
securechain
django-defectdojo_default
```

---

## Verify container connectivity

```bash
docker inspect securechain-defectdojo-integration
```

SC-DOJO must belong to BOTH networks.

---

# 13. Validate End-to-End Workflow

---

## Generate Generic Findings

```bash
curl -X POST http://localhost:8001/api/defectdojo/generic-findings/generate \
-H "Content-Type: application/json" \
-d '{
  "owner":"gti-sos",
  "repository":"SOS2223-JUL-BRB"
}'
```

---

## List documents

```bash
curl http://localhost:8001/api/defectdojo/generic-findings/documents
```

---

## Retrieve document

```bash
curl http://localhost:8001/api/defectdojo/generic-findings/documents/<DOCUMENT_ID>
```

---

## Import into DefectDojo

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

---

# 14. Frontend Validation

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

---

# 15. Running Tests

Inside backend repository:

```bash
uv sync --extra test
```

Run tests:

```bash
uv run pytest -vv
```

---

# 16. Troubleshooting

---

## Nginx upstream host not found

Error:

```text
host not found in upstream "securechain-defectdojo-integration"
```

Cause:
- SC-DOJO container is not running
- frontend and backend are not sharing Docker network

---

## DefectDojo import fails

Common causes:

### Invalid severity

DefectDojo only accepts:

```text
Info
Low
Medium
High
Critical
```

---

### Invalid `mitigated` field

Remove boolean values from:

```json
"mitigated": true
```

It must be a valid datetime or omitted.

---

### Product does not exist

Create Product manually in DefectDojo.

---

## Backend cannot reach DefectDojo

Validate connectivity:

```bash
docker exec -it securechain-defectdojo-integration sh

curl -i http://django-defectdojo-nginx-1:8080/api/v2/products/
```

---

# 17. Useful Commands

---

## Logs

```bash
docker logs securechain-defectdojo-integration --tail=100
```

```bash
docker logs securechain-frontend --tail=100
```

```bash
docker logs django-defectdojo-uwsgi-1 --tail=100
```

---

## Stop containers

```bash
docker compose down
```

---

# License

GNU General Public License v3.0

---

# Authors

SecureChain ↔ DefectDojo Integration — SC-DOJO

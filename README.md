# LockLeaf

LockLeaf is a self-hosted password manager backend built with Django + Django REST Framework.

Only the backend API exists right now. A Chrome extension and mobile app client are planned for the future.

## Other Resoruce
[Chrome Extension](https://github.com/milanbairagi/leaflock-chrome-extension)

## What’s implemented

- User accounts (custom `User` model)
- JWT auth (access + refresh)
- “Master key” setup (stores an encrypted vault key per user)
- Vault unlock flow (short-lived vault unlock token)
- Vault items CRUD (with field-level encryption for sensitive fields)

## Tech stack

- Django
- Django REST Framework
- SimpleJWT (`djangorestframework_simplejwt`)
- SQLite (dev)
- `cryptography`
- `drf-spectacular`

## Local setup (Windows / PowerShell)

From the repo root:

### 1) Create and activate a virtual environment

```powershell
cd coreleaf
py -m venv .venv
.\.venv\Scripts\activate  # On Mac or Linux: source .venv/bin/activate
```

### 2) Install dependencies

```powershell
pip install -r requirements.txt
```

### 3) Environment Setup
Create a `.env` file inside `coreleaf/` directory:
```ini
DJANGO_SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ALLOWED_ORIGINS=http://localhost:5173
USE_REDIS_CACHE=False
REDIS_CACHE_URL=127.0.0.1:6379
```
Replace `your-secret-key` with a secure random key. Generate using:
```powershell
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```
__Make sure to generate a unique `VAULT_UNLOCK_SECRET` that is different from `DJANGO_SECRET_KEY`.__

### 4) Run migrations

```powershell
py manage.py migrate
```

### 5) Start the dev server

```powershell
py manage.py runserver
```

The API will be available at `http://localhost:8000/`.

## API overview

Base URL: `http://localhost:8000/`

### API docs

- OpenAPI schema (JSON): `http://localhost:8000/api/schema/`
- Swagger UI: `http://localhost:8000/api/schema/swagger-ui/`
- ReDoc: `http://localhost:8000/api/schema/redoc/`

### Accounts

- `POST /accounts/register/` - create user
- `POST /accounts/token/` - obtain JWT (access + refresh)
- `POST /accounts/token/refresh/` - refresh access token
- `GET/PATCH /accounts/me/` - get/update current user
- `GET/PATCH /accounts/profile/<id>/` - get/update user by id
- `POST /accounts/master-key/` - set master key (one-time)

### Vaults

- `POST /vaults/unlock/` - exchange master password for a vault unlock token
- `GET/POST /vaults/list-create/` - list or create vault items
- `GET/PATCH /vaults/retrieve-update/<id>/` - retrieve or update a vault item

### Auth headers

- Most endpoints require: `Authorization: Bearer <access_token>`
- Vault item endpoints additionally require: `X-Vault-Unlock-Token: <vault_unlock_token>`

## Testing the API with VS Code REST Client

This repo includes ready-to-run requests in [dev_testing/example.http](dev_testing/example.http).

1) Install the VS Code extension **REST Client** (publisher: Huachao Mao)
2) Open [dev_testing/example.http](dev_testing/example.http)
3) Run the requests in order:

- Register
- Get JWT token
- Set master key (one-time per user)
- Unlock vault (get `vault_unlock_token`)
- List/Create/Retrieve/Update vault items

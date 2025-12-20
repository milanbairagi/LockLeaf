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

## Local setup (Windows / PowerShell)

From the repo root:

1) Create and activate a virtual environment

```powershell
cd coreleaf
py -m venv .venv
.\.venv\Scripts\activate
```

2) Install dependencies

```powershell
pip install -r requirements.txt
```

3) Run migrations

```powershell
py manage.py migrate
```

4) Start the dev server

```powershell
py manage.py runserver
```

The API will be available at `http://localhost:8000/`.

## API overview

Base URL: `http://localhost:8000/`

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

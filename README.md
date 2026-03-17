## Simple Go CRUD API

This repo is a minimal REST **CRUD API** written in Go for a `Book` resource, plus **Keycloak (OIDC) integration** to protect endpoints using JWT access tokens.

## What you’ll build

- **Step 1**: Run the CRUD API locally.
- **Step 2**: Test CRUD with curl/Postman.
- **Step 3**: Start Keycloak locally (Docker).
- **Step 4**: Get a Keycloak access token (password grant).
- **Step 5**: Call protected CRUD endpoints with `Authorization: Bearer <token>`.
- **Step 6 (Visitor view)**: Run the web UI and login via Keycloak in the browser.

## Prerequisites

- Go (1.21+)
- Docker Desktop (to run Keycloak)
- Postman (optional)

### Run

```bash
cd "test crud"
docker compose up -d
go run .
```

Keycloak will start on `http://localhost:8081` and the API will start on `http://localhost:8080`.

### Visitor view (browser UI)

This repo includes a tiny web app that redirects visitors to Keycloak to login, then shows the books page.

Run it in a second terminal:

```bash
cd "test crud"
go run ./cmd/web
```

Open `http://localhost:8082`.

- Login as `user/user` to **view** books
- Login as `adminuser/adminuser` to **create** books (admin role)

Logout note: the web app logs you out from the web session and also redirects to Keycloak logout. If you get “Address already in use” on `:8082`, stop the old process using that port before re-running `go run ./cmd/web`.

### Step-by-step: develop the CRUD first (no auth mindset)

The CRUD API exposes these routes:

- `GET /books` (list)
- `POST /books` (create)
- `GET /books/{id}` (read)
- `PUT/PATCH /books/{id}` (update)
- `DELETE /books/{id}` (delete)

Useful notes while developing/testing:

- `GET /books/1` returns **404** if you haven’t created book `id=1` yet.
- If you run `go run` with no args you’ll see `go: no go files listed`. Use `go run .` instead.

### Keycloak (local)

- **Admin console**: `http://localhost:8081/admin`
  - **Username**: `admin`
  - **Password**: `admin`
- **Realm**: `crud`
- **Client**: `crud-api` (public client, Direct Access Grants enabled)
- **Client (web UI)**: `crud-web` (public client, standard flow)
- **Test users**:
  - **user/user** (role: `crud_user`)
  - **adminuser/adminuser** (roles: `crud_user`, `crud_admin`)

### Step-by-step: Keycloak integration (how it works here)

The API validates JWTs using Keycloak’s **JWKS** endpoint and checks **realm roles**:

- **Read endpoints** (`GET /books`, `GET /books/{id}`): `crud_user` OR `crud_admin`
- **Write endpoints** (`POST/PUT/PATCH/DELETE`): `crud_admin`

Also available:

- `GET /health` is **public** (no token).

### Get an access token (password grant)

As **adminuser** (can write):

```bash
curl -s -X POST "http://localhost:8081/realms/crud/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=crud-api" \
  -d "username=adminuser" \
  -d "password=adminuser"
```

Copy the `access_token` value, then call the API with:

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:8080/books
```

### Postman setup

- **Token request**
  - **Method**: `POST`
  - **URL**: `http://localhost:8081/realms/crud/protocol/openid-connect/token`
  - **Headers**: `Content-Type: application/x-www-form-urlencoded`
  - **Body**: `x-www-form-urlencoded` (this is where you choose the user)
    - `grant_type`: `password`
    - `client_id`: `crud-api`
    - `username`: `adminuser` (or `user`)
    - `password`: `adminuser` (or `user`)
  - Copy `access_token` from the JSON response

- **API request**
  - Add header: `Authorization: Bearer <access_token>`

### Endpoints

- **List books**
  - **GET** `/books`
  - Response: `200 OK` with JSON array of books.

- **Create book**
  - **POST** `/books`
  - Body (JSON):
    ```json
    {
      "title": "My Book",
      "author": "Author Name"
    }
    ```
  - Response: `201 Created` with created book (including `id`).

- **Get single book**
  - **GET** `/books/{id}`
  - Response: `200 OK` with book JSON, or `404 Not Found`.

- **Update book**
  - **PUT/PATCH** `/books/{id}`
  - Body (JSON, any field optional):
    ```json
    {
      "title": "New Title",
      "author": "New Author"
    }
    ```
  - Response: `200 OK` with updated book, or `404 Not Found`.

- **Delete book**
  - **DELETE** `/books/{id}`
  - Response: `204 No Content` on success, or `404 Not Found`.

### Example calls (curl)

Replace `<access_token>` with the token you got from Keycloak.

List (read role required):

```bash
curl -i http://localhost:8080/health
curl -i -H "Authorization: Bearer <access_token>" http://localhost:8080/books
```

Create (admin role required):

```bash
curl -i -X POST http://localhost:8080/books \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"title":"My Book","author":"Author Name"}'
```

### Notes

- Data is stored **in memory only** and will be lost when the server restarts.
- This is intended as a simple starting point; you can replace the `bookStore` implementation with a real database later.
- Auth configuration (optional env vars):
  - `KEYCLOAK_ISSUER` (default `http://localhost:8081/realms/crud`)
  - `KEYCLOAK_JWKS_URL` (default `${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`)

### Troubleshooting

- **`ECONNREFUSED 127.0.0.1:8081`**: Keycloak isn’t running. Start Docker Desktop, then `docker compose up -d`.
- **`{"error":"invalid_grant","error_description":"Account is not fully set up"}`**:
  - In Keycloak admin UI, select realm `crud` → Users → select the user → clear **Required Actions** and set **Email Verified** = ON.
- **`404 page not found` when creating**:
  - Create is **POST** to `/books` (not `/books/1`), and the request must be POST (browser address bar does GET).


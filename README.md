## Simple Go CRUD API

This is a minimal example of a CRUD HTTP API written in Go. It manages an in-memory list of `Book` items and is protected by Keycloak (OIDC) using JWT validation.

### Run

```bash
cd "test crud"
docker compose up -d
go run .
```

Keycloak will start on `http://localhost:8081` and the API will start on `http://localhost:8080`.

### Keycloak (local)

- **Admin console**: `http://localhost:8081/admin`
  - **Username**: `admin`
  - **Password**: `admin`
- **Realm**: `crud`
- **Client**: `crud-api` (public client, Direct Access Grants enabled)
- **Test users**:
  - **user/user** (role: `crud_user`)
  - **adminuser/adminuser** (roles: `crud_user`, `crud_admin`)

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
  - **Body**: `x-www-form-urlencoded`
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

### Notes

- Data is stored **in memory only** and will be lost when the server restarts.
- This is intended as a simple starting point; you can replace the `bookStore` implementation with a real database later.
- Auth configuration (optional env vars):
  - `KEYCLOAK_ISSUER` (default `http://localhost:8081/realms/crud`)
  - `KEYCLOAK_JWKS_URL` (default `${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`)


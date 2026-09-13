# Auth System (C# / .NET)

Sistema de autenticación y autorización reutilizable, construido con ASP.NET Core 10, EF Core + SQLite e Identity. Incluye JWT con access + refresh tokens (rotación y revocación), roles, y verificación en dos pasos (2FA) por TOTP compatible con Google Authenticator / Authy.

## Stack

- ASP.NET Core Web API (.NET 10, controllers)
- ASP.NET Core Identity (`IdentityCore<ApplicationUser>` + roles)
- Entity Framework Core + SQLite
- JWT (access token de corta duración + refresh token rotativo, con hash SHA-256 en base de datos)
- TOTP para 2FA (proveedor `Authenticator` de Identity, sin dependencias externas)

## Cómo correrlo

```bash
cd src/AuthSystem.Api
dotnet restore
dotnet ef database update   # crea authsystem.db y siembra roles Admin/User
dotnet run
```

La API queda en `http://localhost:5080` (o el puerto que indique `dotnet run`). Con `ASPNETCORE_ENVIRONMENT=Development` se expone `/openapi/v1.json`.

> **Nota sobre el secreto JWT:** `appsettings.Development.json` trae una clave de firma de desarrollo, solo para correr el proyecto localmente. Para cualquier despliegue real, sobreescríbela con una variable de entorno (`Jwt__Secret`) o `dotnet user-secrets`, nunca la dejes en el repo.

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/auth/register` | Crea un usuario (rol `User` por defecto) y devuelve tokens |
| POST | `/api/auth/login` | Valida credenciales; si el usuario tiene 2FA activo devuelve `mfaToken` en vez de tokens |
| POST | `/api/auth/login/2fa` | Completa el login con el código TOTP y el `mfaToken` |
| POST | `/api/auth/refresh` | Rota el refresh token (revoca el anterior, emite un par nuevo) |
| POST | `/api/auth/logout` | Revoca un refresh token (requiere estar autenticado) |
| POST | `/api/auth/2fa/setup` | Genera la clave TOTP y el `otpauth://` URI para escanear en el authenticator |
| POST | `/api/auth/2fa/enable` | Activa 2FA tras verificar un código válido |
| POST | `/api/auth/2fa/disable` | Desactiva 2FA tras verificar un código válido |
| GET | `/api/users/me` | Perfil del usuario autenticado (roles, estado de 2FA) |
| GET | `/api/users/admin-ping` | Endpoint de ejemplo protegido por `[Authorize(Roles = "Admin")]` |

## Probar 2FA de punta a punta

1. `POST /api/auth/2fa/setup` (con el access token en `Authorization: Bearer`) → devuelve `sharedKey` y `authenticatorUri`.
2. Cargar `authenticatorUri` en Google Authenticator/Authy (como texto o QR), o calcular el código TOTP con `sharedKey` usando cualquier librería TOTP (ej. `pyotp` en Python).
3. `POST /api/auth/2fa/enable` con el código de 6 dígitos.
4. En el siguiente `POST /api/auth/login`, la respuesta trae `requiresTwoFactor: true` y un `mfaToken` de corta duración.
5. `POST /api/auth/login/2fa` con ese `mfaToken` y el código TOTP actual para recibir los tokens finales.

## Asignar el rol Admin (solo para probar `admin-ping`)

No hay un endpoint público para auto-asignarse el rol `Admin` (a propósito: eso sería un hueco de seguridad). Para probar `admin-ping` en local, asígnalo directamente en la base de datos:

```bash
sqlite3 src/AuthSystem.Api/authsystem.db \
  "INSERT INTO AspNetUserRoles (UserId, RoleId)
   SELECT u.Id, r.Id FROM AspNetUsers u, AspNetRoles r
   WHERE u.Email = 'test@example.com' AND r.Name = 'Admin';"
```

## Estructura

```
src/AuthSystem.Api/
  Controllers/      AuthController, UsersController
  Data/              AppDbContext, RoleSeeder, migraciones EF
  Dtos/              Contratos de request/response
  Models/            ApplicationUser, RefreshToken
  Options/           JwtOptions
  Services/          TokenService (JWT + refresh), MfaChallengeStore (desafíos 2FA pendientes)
```

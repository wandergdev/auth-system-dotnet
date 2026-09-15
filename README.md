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
dotnet user-secrets set "Jwt:Secret" "$(openssl rand -base64 48)"   # ver "Secreto de firma (Jwt:Secret)"
dotnet ef database update   # crea authsystem.db y siembra roles Admin/User
dotnet run
```

La API queda en **`http://localhost:5073`** (perfil `http` de `launchSettings.json`). El perfil `https` levanta además `https://localhost:7185`. Con `ASPNETCORE_ENVIRONMENT=Development` se expone `/openapi/v1.json`.

`launchSettings.json` solo aplica a `dotnet run` en local; en un despliegue el puerto lo define `ASPNETCORE_URLS` (o el host/contenedor).

## Secreto de firma (`Jwt:Secret`)

La clave con la que se firman los access tokens **nunca vive en un archivo commiteado**. No hay valor por defecto: si `Jwt:Secret` falta, o mide menos de 32 bytes, la API **falla al arrancar** con un mensaje explícito en vez de levantar con una llave insegura (HS256 exige una clave de 256 bits como mínimo).

Generar una llave nueva:

```bash
openssl rand -base64 48
```

Configurarla en desarrollo (se guarda fuera del repo, en el secret store del usuario):

```bash
cd src/AuthSystem.Api
dotnet user-secrets set "Jwt:Secret" "<la llave generada>"
dotnet user-secrets list          # verificar
```

Configurarla en despliegue, con la variable de entorno equivalente (el doble guion bajo es el separador de secciones de .NET):

```bash
export Jwt__Secret="<la llave generada>"
```

> **Rotar la llave invalida todos los access tokens al instante.** Como la misma llave la usan las APIs consumidoras para verificar (ver más abajo), hay que actualizarla en este servicio y en cada consumidor **en el mismo momento**. Los refresh tokens sobreviven a la rotación: están hasheados en base de datos, no firmados con esta llave, así que los clientes se recuperan con `POST /api/auth/refresh`.

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

## Integrar una API consumidora

Este servicio es el único que emite tokens. Una API consumidora (por ejemplo `finance-api`) solo los **verifica**: no toca la base de datos de usuarios ni guarda contraseñas.

### Contrato del access token

Header:

```json
{ "alg": "HS256", "typ": "JWT" }
```

Payload (ejemplo real, recortado):

```json
{
  "sub": "9a6e7f7a-1890-4a25-a41f-c984c772cafd",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "9a6e7f7a-1890-4a25-a41f-c984c772cafd",
  "email": "user@example.com",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "user@example.com",
  "jti": "c9d99b87-002b-4a32-ae1d-ca7427976ce1",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "User",
  "exp": 1789499548,
  "iss": "AuthSystem",
  "aud": "AuthSystem.Clients"
}
```

| Claim | Contenido | Nota |
|---|---|---|
| `sub` | Guid del usuario | Identificador estable. Es el que hay que usar como id local |
| `…/claims/nameidentifier` | El mismo Guid | Forma larga de `ClaimTypes.NameIdentifier`, emitida a la par de `sub` |
| `email` | Email del usuario | Puede cambiar: no lo uses como clave primaria |
| `…/claims/emailaddress` | El mismo email | Forma larga de `ClaimTypes.Email` |
| `…/claims/role` | Rol, o **array** de roles si el usuario tiene más de uno | Hoy: `Admin`, `User` |
| `jti` | Id único del token | Útil para trazas o una denylist |
| `exp` | Expiración (epoch en segundos) | 15 minutos después de la emisión |
| `iss` | `AuthSystem` | Debe validarse |
| `aud` | `AuthSystem.Clients` | Debe validarse |

Dos detalles que sorprenden si no se leen antes:

- **Los roles se emiten solo en la forma larga**, `http://schemas.microsoft.com/ws/2008/06/identity/claims/role`. No hay un claim corto `role`. Un consumidor que busque `payload.role` no va a encontrar nada.
- **No se emiten `iat` ni `nbf`.** El consumidor no puede deducir la duración del token desde el payload; solo tiene `exp`.

`sub`, `email` y sus equivalentes largos se emiten duplicados a propósito: el `JwtBearerHandler` de ASP.NET Core ya no mapea los nombres cortos a `ClaimTypes.*`, pero `UserManager`/`User.Identity` sí dependen de la forma larga. Así funcionan ambos caminos.

### Qué DEBE validar el consumidor

No alcanza con decodificar el token. Un verificador correcto valida **las cuatro cosas**:

1. **La firma**, con la misma llave `Jwt:Secret` de este servicio.
2. **`iss` = `AuthSystem`**.
3. **`aud` = `AuthSystem.Clients`**.
4. **El algoritmo, fijado explícitamente a `HS256`.**

El punto 4 no es opcional. Si la librería acepta el algoritmo que venga en el header del token, un atacante puede cambiar `alg` a `none` (token sin firma) o, en un futuro despliegue con RSA, firmar con HMAC usando la clave pública como secreto: son los **ataques de confusión de algoritmo**. Fijar la lista de algoritmos permitidos los cierra.

Este servicio valida la expiración con un margen (`ClockSkew`) de 30 segundos; conviene que el consumidor use un margen parecido en vez del default de 5 minutos de muchas librerías.

En Node/Express (`jsonwebtoken`):

```js
const jwt = require("jsonwebtoken");

const ROLE_CLAIM = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization || "").split(" ");
  if (scheme !== "Bearer" || !token) return res.sendStatus(401);

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],          // obligatorio: cierra la confusión de algoritmo
      issuer: "AuthSystem",
      audience: "AuthSystem.Clients",
      clockTolerance: 30,
    });

    const roles = [].concat(payload[ROLE_CLAIM] ?? []);   // string o array
    req.user = { id: payload.sub, email: payload.email, roles };
    next();
  } catch {
    res.sendStatus(401);
  }
}
```

En otra API .NET, el equivalente es `AddJwtBearer` con `ValidateIssuer`, `ValidateAudience`, `ValidateIssuerSigningKey` y `ValidAlgorithms = [SecurityAlgorithms.HmacSha256]`.

### Ciclo de vida del token en el cliente

El access token dura **15 minutos**; el refresh token, **7 días**. El cliente (no la API consumidora) es quien renueva:

1. Guarda `accessToken` y `refreshToken` del login.
2. Cuando la API consumidora responde `401`, llama a `POST /api/auth/refresh` de **este** servicio con el `refreshToken`.
3. Recibe un par nuevo y reintenta la petición original.

La rotación es estricta: cada `refresh` revoca el token usado y emite uno nuevo. Un refresh token **no se puede reutilizar**; el cliente tiene que guardar siempre el último que recibió, o el usuario queda deslogueado.

La API consumidora nunca llama a `/api/auth/refresh`: para ella un token expirado es simplemente un `401`.

### Espejar el usuario en el consumidor

No dupliques credenciales. La API consumidora no debe tener tabla de contraseñas, ni de 2FA, ni llamar a este servicio en cada request.

En su lugar, usa `sub` (el Guid) como id de usuario en tu propio esquema, y crea la fila local la primera vez que ves ese `sub` en un token válido:

```sql
-- en finance-api, no aquí
CREATE TABLE users (
  id    UUID PRIMARY KEY,   -- el "sub" del token, tal cual
  email TEXT,               -- copia de conveniencia, refrescable desde el token
  ...
);
```

Ventajas: los datos de negocio quedan referenciados a un id estable, el email puede cambiar sin romper nada, y no hay una segunda copia de credenciales que mantener sincronizada ni que se pueda filtrar.

## Probar 2FA de punta a punta

1. `POST /api/auth/2fa/setup` (con el access token en `Authorization: Bearer`) → devuelve `sharedKey` y `authenticatorUri`.
2. Cargar `authenticatorUri` en Google Authenticator/Authy (como texto o QR), o calcular el código TOTP con `sharedKey` usando cualquier librería TOTP (ej. `pyotp` en Python).
3. `POST /api/auth/2fa/enable` con el código de 6 dígitos.
4. En el siguiente `POST /api/auth/login`, la respuesta trae `requiresTwoFactor: true` y un `mfaToken` de corta duración.
5. `POST /api/auth/login/2fa` con ese `mfaToken` y el código TOTP actual para recibir los tokens finales.

> El `mfaToken` es de **un solo uso, se acierte o no el código**: se consume al primer intento. Si el usuario tecleó mal el código, el cliente tiene que volver a `POST /api/auth/login` para pedir un desafío nuevo. Es deliberado —evita que un `mfaToken` robado aguante intentos de fuerza bruta durante sus 5 minutos de vida—, pero el cliente tiene que contemplarlo en su UI.

## Asignar el rol Admin (solo para probar `admin-ping`)

No hay un endpoint público para auto-asignarse el rol `Admin` (a propósito: eso sería un hueco de seguridad). Para probar `admin-ping` en local, asígnalo directamente en la base de datos:

```bash
sqlite3 src/AuthSystem.Api/authsystem.db \
  "INSERT INTO AspNetUserRoles (UserId, RoleId)
   SELECT u.Id, r.Id FROM AspNetUsers u, AspNetRoles r
   WHERE u.Email = 'test@example.com' AND r.Name = 'Admin';"
```

## Limitaciones operativas

### El servicio es single-instance hoy

`Services/MfaChallengeStore.cs` guarda los desafíos de 2FA pendientes (el `mfaToken` que devuelve `/api/auth/login` y que consume `/api/auth/login/2fa`) en `IMemoryCache`, es decir **en la memoria del proceso**.

Consecuencia concreta: si corren dos instancias detrás de un balanceador, un usuario con 2FA puede hacer `login` contra la instancia A y que su `login/2fa` caiga en la instancia B, que no conoce ese `mfaToken` y responde `401`. El login con 2FA fallaría de forma intermitente, dependiendo del balanceo.

Por eso, **mientras el store sea en memoria, este servicio debe desplegarse en una sola instancia.** Lo mismo aplica a reinicios: un deploy invalida los desafíos en vuelo (con un TTL de 5 minutos, la ventana es corta y el usuario solo tiene que volver a hacer login).

El resto del estado ya es compartible: usuarios, roles y refresh tokens viven en la base de datos, no en memoria.

Para escalar horizontalmente haría falta:

1. Mover los desafíos a un store distribuido —Redis vía `IDistributedCache`, o una tabla en la base de datos con su TTL— manteniendo la interfaz `IMfaChallengeStore` (`CreateChallenge` / `ConsumeChallenge`) para no tocar `AuthController`.
2. Que el consumo del desafío siga siendo **atómico y de un solo uso**, para que dos instancias no puedan canjear el mismo `mfaToken` a la vez (`GETDEL` en Redis, o un `DELETE ... RETURNING` en SQL).
3. Cambiar SQLite por un motor con acceso concurrente real (PostgreSQL, SQL Server): SQLite en un archivo local no se comparte entre instancias.

Alternativa sin store compartido: firmar el `mfaToken` como un JWT de corta duración con la misma llave. Evita la infraestructura extra, pero pierde el consumo de un solo uso —cualquier instancia lo aceptaría hasta que expire— salvo que se agregue igualmente una denylist compartida.

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

# Auth System (C# / .NET)

Servicio de identidad reutilizable: emite y valida los tokens de varias aplicaciones a la vez.
Construido con ASP.NET Core 10, EF Core + PostgreSQL e Identity. Incluye JWT firmado con RS256,
refresh tokens rotativos, audiencias y roles por aplicación, y 2FA por TOTP.

## Stack

- ASP.NET Core Web API (.NET 10, controllers)
- ASP.NET Core Identity (`IdentityCore<ApplicationUser>` + roles por aplicación)
- Entity Framework Core + PostgreSQL (Npgsql)
- JWT firmado con **RS256**, con JWKS público en `/.well-known/jwks.json`
- Access token de 15 min + refresh token rotativo de 7 días, hasheado en base de datos
- TOTP para 2FA (proveedor `Authenticator` de Identity, sin dependencias externas)

## Cómo correrlo

```bash
# 1. Base de datos
docker compose up -d                 # PostgreSQL 17 en localhost:5434

# 2. Llave de firma (obligatoria: sin ella la API no arranca)
cd src/AuthSystem.Api
dotnet user-secrets set "Jwt:PrivateKey" \
  "$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\n')"

# 3. Arrancar
dotnet run
```

**No hace falta `dotnet ef database update`.** Al arrancar, la aplicación aplica las migraciones
pendientes y siembra los datos iniciales por sí sola (`Program.cs`). El comando de EF solo aplica el
esquema; no siembra nada, así que usarlo en lugar de arrancar deja la base a medias.

En el primer arranque se crean:

- La aplicación cliente `default`, con audiencia `AuthSystem.Clients`.
- Sus roles `default:Admin` y `default:User`.

La API queda en **`http://localhost:5073`** (perfil `http` de `launchSettings.json`). El perfil
`https` añade `https://localhost:7185`. En Development se expone `/openapi/v1.json`.

`launchSettings.json` solo aplica a `dotnet run` en local; en un despliegue el puerto lo define
`ASPNETCORE_URLS` o el contenedor, y la cadena de conexión viene de `ConnectionStrings__Default`
(el `docker-compose.yml` es solo para desarrollo).

## Configuración

Todo vive bajo la sección `Jwt` de `appsettings.json`, salvo los secretos. En variables de entorno,
el separador de secciones es doble guion bajo: `Jwt:PrivateKey` → `Jwt__PrivateKey`.

| Clave | Por defecto | Qué hace |
|---|---|---|
| `Jwt:Algorithm` | `RS256` | Algoritmo de firma. `RS256` o `HS256` |
| `Jwt:PrivateKey` | *(sin valor)* | Llave privada RSA. **Obligatoria con RS256.** Nunca en el repo |
| `Jwt:PreviousPublicKey` | *(sin valor)* | Pública saliente durante una rotación. Solo valida, nunca firma |
| `Jwt:Secret` | *(sin valor)* | Llave simétrica HS256. Obligatoria solo si `Algorithm` es `HS256` |
| `Jwt:AcceptLegacyHs256` | `true` | Sigue aceptando tokens HS256 emitidos antes de migrar a RS256 |
| `Jwt:Issuer` | `AuthSystem` | Valor del claim `iss` |
| `Jwt:AccessTokenMinutes` | `15` | Vida del access token |
| `Jwt:RefreshTokenDays` | `7` | Vida del refresh token |
| `Jwt:MfaChallengeMinutes` | `5` | Vida del `mfaToken` de 2FA |
| `ConnectionStrings:Default` | Postgres en 5434 | Cadena de conexión |

No hay clave de audiencia: **la audiencia sale del registro de aplicaciones**, no de la configuración.

## Llaves de firma

La clave privada la conoce solo este servicio. Las APIs consumidoras leen la pública del JWKS, así
que **pueden verificar pero no emitir**. Ninguna llave se commitea.

Si falta la llave, no se puede leer, o es más débil de lo que el algoritmo exige, la API **falla al
arrancar** con un mensaje que indica el comando exacto a ejecutar.

### Generar

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\n'
```

Mínimo **2048 bits**; una llave menor se rechaza al arrancar. Se aceptan cuatro formatos, porque las
herramientas no coinciden entre sí (el `genpkey` de LibreSSL en macOS escribe PKCS#8 en PEM pero
PKCS#1 en DER):

- PEM (`-----BEGIN PRIVATE KEY-----` o `-----BEGIN RSA PRIVATE KEY-----`)
- base64 de ese PEM ← **recomendado para variables de entorno**: cabe en una línea
- base64 del DER PKCS#8
- base64 del DER PKCS#1

### Configurar

```bash
# desarrollo (fuera del repo)
cd src/AuthSystem.Api
dotnet user-secrets set "Jwt:PrivateKey" "<llave>"
dotnet user-secrets list

# despliegue
export Jwt__PrivateKey="<llave>"
```

### Rotar sin downtime

Publicando las dos llaves durante la ventana, la rotación no corta a nadie ni requiere tocar a los
consumidores: la recogen del JWKS por su `kid`.

```bash
# 1. exportar la pública de la llave que sale
openssl pkey -pubout -in llave-actual.pem | base64 | tr -d '\n'   # -> Jwt__PreviousPublicKey

# 2. generar la entrante
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\n'  # -> Jwt__PrivateKey

# 3. desplegar con ambas; pasados >15 min, quitar Jwt__PreviousPublicKey
```

Durante la ventana el JWKS expone las dos llaves, los tokens firmados con la saliente siguen
validando hasta expirar, y los consumidores con el JWKS anterior en caché siguen funcionando. La
saliente **solo valida, nunca vuelve a firmar**.

Los refresh tokens son ajenos a la rotación: están hasheados en base de datos, no firmados.

### `Jwt:Secret` (HS256, en retirada)

Mientras `Jwt:AcceptLegacyHs256` sea `true`, la llave simétrica se sigue leyendo **solo para
validar** tokens emitidos antes de migrar a RS256. Ya no firma nada.

Cuando no pueda quedar ningún token HS256 vivo (su ventana es de 15 min; en la práctica, al día
siguiente), cierra la transición con `"AcceptLegacyHs256": false` y borra `Jwt:Secret` del entorno y
de user-secrets. Hasta entonces, quien tenga esa llave puede emitir tokens que este servicio acepta.

## Endpoints

| Método | Ruta | Auth | Descripción |
|---|---|---|---|
| POST | `/api/auth/register` | — | Crea un usuario, le da el rol `User` de la aplicación indicada y devuelve tokens |
| POST | `/api/auth/login` | — | Valida credenciales. Con 2FA activo devuelve `mfaToken` en vez de tokens |
| POST | `/api/auth/login/2fa` | — | Completa el login con el `mfaToken` y el código TOTP |
| POST | `/api/auth/refresh` | — | Rota el refresh token: revoca el usado y emite un par nuevo |
| POST | `/api/auth/logout` | Bearer | Revoca un refresh token |
| POST | `/api/auth/2fa/setup` | Bearer | Genera la clave TOTP y el URI `otpauth://` |
| POST | `/api/auth/2fa/enable` | Bearer | Activa 2FA tras verificar un código |
| POST | `/api/auth/2fa/disable` | Bearer | Desactiva 2FA tras verificar un código |
| GET | `/api/users/me` | Bearer | Perfil y roles del usuario **en la aplicación del token** |
| GET | `/api/users/admin-ping` | Bearer + rol `Admin` | Ejemplo de autorización por rol |
| GET | `/api/applications` | Bearer + **SystemAdmin** | Lista las aplicaciones registradas |
| POST | `/api/applications` | Bearer + **SystemAdmin** | Registra una aplicación consumidora |
| POST | `/api/applications/{clientId}/deactivate` | Bearer + **SystemAdmin** | Desactiva una aplicación |
| GET | `/.well-known/jwks.json` | Público | Clave(s) pública(s) de firma |
| GET | `/.well-known/openid-configuration` | Público | Descubrimiento mínimo |

**SystemAdmin** no es lo mismo que el rol `Admin`: exige el rol `Admin` **y** que el token se haya
emitido para la aplicación `default`. Ser Admin del CRM te hace administrador *del CRM*, no de este
servicio — de lo contrario podrías crear audiencias y desactivar aplicaciones ajenas.

Los endpoints propios del servicio (`/api/users/*`, `/api/auth/2fa/*`, `logout`) aceptan un token
emitido para **cualquier** aplicación registrada: el token acredita quién eres, y esos endpoints
gestionan tu propia cuenta.

## Formato de respuestas

`register`, `login/2fa` y `refresh` devuelven:

```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6InM4U1dEb2JN...",
  "refreshToken": "CsgmOxs0eU1byFy7R2ubW+rfmgDBJDEDpP2AhBmcQ6HNPNTohll7t+cox4ypjAZeJYiw2sG0szfoAaMGAklVpA==",
  "accessTokenExpiresAtUtc": "2026-09-15T20:15:27.203524Z"
}
```

El `refreshToken` es base64 estándar: contiene `+`, `/` y `=`. Va siempre en el cuerpo JSON, nunca en
una URL sin escapar.

`login` envuelve eso en:

```json
{ "requiresTwoFactor": false, "mfaToken": null, "tokens": { ... } }
```

y con 2FA activo: `{ "requiresTwoFactor": true, "mfaToken": "...", "tokens": null }`.

`GET /api/users/me`:

```json
{
  "id": "01a0a6a8-1000-7eed-9f1c-2ece1d811a3f",
  "email": "user@example.com",
  "twoFactorEnabled": false,
  "roles": ["User"]
}
```

### Errores

Hay **dos formatos distintos**, y un cliente tiene que contemplar los dos:

Errores de negocio — objeto con `message`:

```json
// 401 credenciales incorrectas
{ "message": "Credenciales inválidas." }
// 409 email ya registrado
{ "message": "Ya existe una cuenta con ese email." }
// 400 clientId desconocido
{ "message": "La aplicación 'no-existe' no existe o está inactiva." }
```

Errores de validación del DTO — `ProblemDetails` estándar de ASP.NET Core:

```json
{
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.1",
  "title": "One or more validation errors occurred.",
  "status": 400,
  "errors": { "Password": ["The field Password must be a string or array type with a minimum length of '8'."] }
}
```

Un `register` que falle por las reglas de contraseña de Identity devuelve además
`{ "errors": ["..."] }` con las descripciones de Identity.

## Integrar una API consumidora

Este servicio es el único que emite tokens. Una API consumidora solo los **verifica**: no toca la
base de datos de usuarios ni guarda contraseñas.

### Contrato del access token

Header:

```json
{ "alg": "RS256", "kid": "s8SWDobMqoed8cvZ8-S6ngOMbchKaty1sywz-uGODlk", "typ": "JWT" }
```

El `kid` identifica la llave del JWKS con la que verificar. Se deriva del thumbprint de la llave
(RFC 7638), así que es estable y reproducible.

Payload (capturado de un token real):

```json
{
  "sub": "01a0a6a8-1000-7eed-9f1c-2ece1d811a3f",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "01a0a6a8-1000-7eed-9f1c-2ece1d811a3f",
  "email": "user@example.com",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "user@example.com",
  "jti": "2f6b9169-7eeb-4e73-af5d-c4164a694a09",
  "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "User",
  "exp": 1789503327,
  "iss": "AuthSystem",
  "aud": "AuthSystem.Clients"
}
```

| Claim | Contenido | Nota |
|---|---|---|
| `sub` | Guid del usuario | Identificador estable. Úsalo como id local |
| `…/claims/nameidentifier` | El mismo Guid | Forma larga de `ClaimTypes.NameIdentifier` |
| `email` | Email | Puede cambiar: no lo uses como clave primaria |
| `…/claims/emailaddress` | El mismo email | Forma larga de `ClaimTypes.Email` |
| `…/claims/role` | Rol, o **array** si hay más de uno | Solo los de **esta** aplicación, sin prefijo |
| `jti` | Id único del token | Para trazas o una denylist |
| `exp` | Expiración (epoch en segundos) | 15 min tras la emisión |
| `iss` | `AuthSystem` | Debe validarse |
| `aud` | Audiencia **de la aplicación** | Debe validarse. `AuthSystem.Clients` para `default` |

Tres detalles que sorprenden si no se leen antes:

- **Los roles se emiten solo en la forma larga**, `http://schemas.microsoft.com/ws/2008/06/identity/claims/role`.
  No existe un claim corto `role`: quien busque `payload.role` no encontrará nada.
- **No se emiten `iat` ni `nbf`.** No puedes deducir la duración desde el payload; solo tienes `exp`.
- **`aud` depende de la aplicación**, no es una constante del sistema. Cada consumidor valida la suya.

`sub`/`email` se duplican en forma corta y larga a propósito: el `JwtBearerHandler` ya no mapea los
nombres cortos a `ClaimTypes.*`, pero `UserManager`/`User.Identity` dependen de la forma larga.

### Qué DEBE validar el consumidor

No basta con decodificar. Un verificador correcto valida **las cuatro**:

1. **La firma**, con la clave pública de `/.well-known/jwks.json`.
2. **`iss` = `AuthSystem`**.
3. **`aud` = la audiencia de esta aplicación** (no la de otra).
4. **El algoritmo, fijado explícitamente a `RS256`.**

El punto 4 no es opcional. Si la librería acepta el `alg` que venga en el header, un atacante puede
ponerlo en `none`, o firmar con HMAC usando **la clave pública como secreto** — y esa clave es, por
diseño, pública. Son los **ataques de confusión de algoritmo**. Fijar la lista los cierra. Este
servicio los rechaza y el consumidor debe hacer lo mismo.

Este servicio valida la expiración con un `ClockSkew` de **30 segundos**; conviene que el consumidor
use un margen parecido, en vez del default de 5 minutos de muchas librerías.

### Node / Express

```js
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const ROLE_CLAIM = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

const client = jwksClient({
  jwksUri: `${process.env.AUTH_SERVICE_URL}/.well-known/jwks.json`,
  cache: true,               // no golpear al auth en cada request
  cacheMaxAge: 3600_000,
  rateLimit: true,
});

// Resolver la llave por el kid del header: nunca probar llaves "a ver cuál pega".
const getKey = (header, cb) =>
  client.getSigningKey(header.kid, (err, key) => cb(err, key && key.getPublicKey()));

function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization || "").split(" ");
  if (scheme !== "Bearer" || !token) return res.sendStatus(401);

  jwt.verify(token, getKey, {
    algorithms: ["RS256"],                 // obligatorio
    issuer: "AuthSystem",
    audience: process.env.AUTH_AUDIENCE,   // la audiencia DE ESTA app
    clockTolerance: 30,
  }, (err, payload) => {
    if (err) return res.sendStatus(401);
    const roles = [].concat(payload[ROLE_CLAIM] ?? []);   // string o array
    req.user = { id: payload.sub, email: payload.email, roles };
    next();
  });
}
```

> **Durante la migración desde HS256**, si necesitas aceptar ambos algoritmos, pasa
> `algorithms: ["RS256", "HS256"]` **y resuelve la llave según `header.alg`**: la pública solo para
> `RS256`, el secreto HMAC solo para `HS256`. Si dejas que la librería pruebe ambas contra el mismo
> material, reabres el ataque que el punto 4 cierra. Quita `HS256` en cuanto puedas.

### Otra API .NET

Apuntando al issuer no hay que configurar llaves a mano — descubre el JWKS por
`/.well-known/openid-configuration`:

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.Authority = "http://localhost:5073";
        o.RequireHttpsMetadata = false;   // solo en local; en despliegue usa https y quítalo
        o.Audience = "AuthSystem.Clients";
        o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256];
    });
```

`RequireHttpsMetadata = false` es imprescindible mientras el auth corra por HTTP: sin él el handler
se niega a descargar el documento de descubrimiento.

### Ciclo de vida del token

Access token **15 min**, refresh token **7 días**. Renueva el cliente, no la API consumidora:

1. Guarda `accessToken` y `refreshToken` del login.
2. Cuando la API consumidora responde `401`, llama a `POST /api/auth/refresh` de **este** servicio.
3. Recibe un par nuevo y reintenta la petición original.

La rotación es estricta: cada `refresh` revoca el token usado. Un refresh token **no se reutiliza**;
guarda siempre el último, o el usuario queda deslogueado. El refresh mantiene la aplicación: nunca
devuelve un token para otra audiencia.

La API consumidora nunca llama a `/api/auth/refresh`: para ella, un token expirado es un `401`.

### Espejar el usuario

No dupliques credenciales. Usa `sub` como id en tu propio esquema y crea la fila local la primera vez
que veas ese `sub` en un token válido:

```sql
-- en el consumidor, no aquí
CREATE TABLE users (
  id    UUID PRIMARY KEY,   -- el "sub" del token, tal cual
  email TEXT,               -- copia de conveniencia, refrescable desde el token
  ...
);
```

Así los datos de negocio referencian un id estable, el email puede cambiar sin romper nada, y no hay
una segunda copia de credenciales que sincronizar ni que se pueda filtrar.

## Varias aplicaciones consumidoras

Cada aplicación se registra una vez y recibe **su propia audiencia**. Un token del CRM es rechazado
por finance-api y viceversa: si la app menos cuidadosa filtra un token, ese token no abre las demás.

### Registrar una aplicación

Requiere un token **SystemAdmin** (rol `Admin` en la aplicación `default`):

```bash
curl -X POST http://localhost:5073/api/applications \
  -H "Authorization: Bearer <token SystemAdmin>" \
  -H "Content-Type: application/json" \
  -d '{"clientId":"crm-app","audience":"crm.myorg.app","displayName":"CRM"}'
```

Devuelve `201` y crea automáticamente los roles `crm-app:Admin` y `crm-app:User`. El `clientId` y la
audiencia son únicos: repetir cualquiera de los dos devuelve `409`.

`POST /api/applications/{clientId}/deactivate` la desactiva — deja de emitir tokens y los existentes
fallan la validación de audiencia, sin borrar roles ni asignaciones. La aplicación `default` no se
puede desactivar (`400`).

### Pedir un token para una aplicación

```jsonc
POST /api/auth/login
{ "email": "...", "password": "...", "clientId": "crm-app" }   // -> aud: "crm.myorg.app"
```

**`clientId` es opcional** en `register` y `login`. Omitirlo usa la aplicación `default`, cuya
audiencia es `AuthSystem.Clients` — la misma que ya validaban los consumidores anteriores, así que no
hubo que cambiarlos. Un `clientId` desconocido o inactivo devuelve `400`.

`login/2fa` y `refresh` **no** llevan `clientId`: lo heredan del desafío o del refresh token, para
que no se pueda saltar de una aplicación a otra a mitad del flujo.

### Roles por aplicación

Un rol pertenece a una aplicación: puedes ser `Admin` en el CRM y `User` en finance. En base de datos
se guardan cualificados (`crm-app:Admin`) porque Identity exige nombres de rol únicos, pero el token
lleva solo el nombre simple, y `GET /api/users/me` devuelve igualmente los de la aplicación del token:

```jsonc
// token para crm-app          // token para default
"...claims/role": "Admin"      "...claims/role": "User"
```

El consumidor no ve el prefijo ni necesita saber que existe.

### Añadir la aplicación número 100

No toca este repositorio. Se registra por API, las audiencias se recargan solas en todas las
instancias (snapshot de 60 s) y el consumidor nuevo solo necesita la URL del servicio para leer el
JWKS. No se reparte ningún secreto.

## Probar 2FA de punta a punta

1. `POST /api/auth/2fa/setup` con el access token → devuelve `sharedKey` y `authenticatorUri`.
2. Carga `authenticatorUri` en Google Authenticator/Authy, o calcula el código con `sharedKey` y
   cualquier librería TOTP (`pyotp` en Python).
3. `POST /api/auth/2fa/enable` con el código de 6 dígitos → `204`.
4. El siguiente `POST /api/auth/login` responde `requiresTwoFactor: true` y un `mfaToken`.
5. `POST /api/auth/login/2fa` con ese `mfaToken` y el código actual → tokens.

> El `mfaToken` es de **un solo uso, se acierte o no el código**: se consume en el primer intento. Si
> el usuario se equivoca, el cliente debe volver a `POST /api/auth/login` por un desafío nuevo. Es
> deliberado —impide fuerza bruta durante los 5 minutos de vida del desafío— pero la UI del cliente
> tiene que contemplarlo.

## Asignar el rol Admin

No hay endpoint para auto-asignarse `Admin` (sería un hueco de seguridad). Para el primer
administrador, asígnalo en base de datos:

```bash
docker exec authsystem-db psql -U authsystem -d authsystem -c \
  'INSERT INTO "AspNetUserRoles" ("UserId", "RoleId")
   SELECT u."Id", r."Id" FROM "AspNetUsers" u, "AspNetRoles" r
   WHERE u."Email" = '"'"'test@example.com'"'"' AND r."Name" = '"'"'default:Admin'"'"';'
```

El nombre del rol va **cualificado** (`default:Admin`) porque los roles pertenecen a una aplicación.
Hay que **volver a hacer login** para que el rol aparezca en un token nuevo.

Ese usuario, con un token de la aplicación `default`, es SystemAdmin y ya puede registrar
aplicaciones.

## Escalado horizontal

El servicio **puede correr en varias instancias detrás de un balanceador**. Todo el estado compartido
vive en PostgreSQL:

- **Usuarios, roles, aplicaciones y refresh tokens**: en base de datos.
- **Desafíos 2FA pendientes** (`MfaChallenges`): antes en `IMemoryCache`, lo que obligaba a una sola
  instancia — un `login` atendido por A y un `login/2fa` que cayera en B fallaba con `401`. Ahora
  cualquier instancia los canjea.
- El canje es **atómico y de un solo uso**: un `DELETE ... RETURNING` resuelve lectura y borrado en
  una sentencia, así que dos instancias compitiendo por el mismo `mfaToken` no pueden canjearlo las
  dos. Verificado con 20 intentos concurrentes: exactamente uno gana.
- Del `mfaToken` solo se guarda el hash SHA-256: una fuga de la base no permite completar logins.
- **Las audiencias se recargan solas**: cada instancia mantiene un snapshot en memoria que refresca
  cada 60 s, así que registrar una aplicación se propaga sin reiniciar ni coordinar nada.

Lo único por instancia es ese snapshot, y es una caché: reconstruirlo es una consulta. Como
consecuencia, **registrar o desactivar una aplicación puede tardar hasta 60 s en verse en las demás
instancias** (en la que atiende la petición es inmediato).

Los desafíos caducan solos (TTL de 5 min) y quedan inutilizables aunque no se borren;
`DbMfaChallengeStore.RemoveExpiredAsync` limpia la tabla cuando se quiera programar.

## Estructura

```
src/AuthSystem.Api/
  Authorization/    SystemAdminRequirement + handler (administración del registro)
  Controllers/      AuthController, UsersController, ClientApplicationsController,
                    WellKnownController (JWKS y descubrimiento)
  Data/             AppDbContext, DataSeeder, migraciones EF
  Dtos/             Contratos de request/response
  Models/           ApplicationUser, ApplicationRole, ClientApplication,
                    RefreshToken, MfaChallenge
  Options/          JwtOptions
  Services/         TokenService (JWT + refresh), JwtKeyProvider (llaves + JWKS),
                    ClientApplicationService (registro de apps), DbMfaChallengeStore
docker-compose.yml  PostgreSQL 17 para desarrollo (puerto 5434)
```

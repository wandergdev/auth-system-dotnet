# Auth System (C# / .NET)

Sistema de autenticación y autorización reutilizable, construido con ASP.NET Core 10, EF Core + PostgreSQL e Identity. Incluye JWT con access + refresh tokens (rotación y revocación), roles, y verificación en dos pasos (2FA) por TOTP compatible con Google Authenticator / Authy.

## Stack

- ASP.NET Core Web API (.NET 10, controllers)
- ASP.NET Core Identity (`IdentityCore<ApplicationUser>` + roles)
- Entity Framework Core + **PostgreSQL**
- JWT firmado con **RS256** (RSA asimétrico), con JWKS público en `/.well-known/jwks.json`
- Access token de corta duración + refresh token rotativo, con hash SHA-256 en base de datos
- TOTP para 2FA (proveedor `Authenticator` de Identity, sin dependencias externas)

## Cómo correrlo

```bash
docker compose up -d          # Postgres en localhost:5434

cd src/AuthSystem.Api
dotnet restore
dotnet user-secrets set "Jwt:PrivateKey" \
  "$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\n')"
dotnet ef database update     # crea el esquema y siembra roles
dotnet run
```

El `docker-compose.yml` levanta PostgreSQL 17 en el puerto **5434** (para no chocar con un Postgres
nativo en 5432 ni con otros proyectos). En despliegue, la cadena de conexión se pasa por
`ConnectionStrings__Default` y este compose no se usa.

La API queda en **`http://localhost:5073`** (perfil `http` de `launchSettings.json`). El perfil `https` levanta además `https://localhost:7185`. Con `ASPNETCORE_ENVIRONMENT=Development` se expone `/openapi/v1.json`.

`launchSettings.json` solo aplica a `dotnet run` en local; en un despliegue el puerto lo define `ASPNETCORE_URLS` (o el host/contenedor).

## Llaves de firma

El servicio firma los access tokens con **RS256** (RSA, asimétrico). La clave privada la conoce solo
este servicio; las APIs consumidoras obtienen la pública del endpoint JWKS y **solo pueden verificar,
no emitir**. Ninguna llave vive en un archivo commiteado.

Si falta la llave, o es inválida, o es más corta de lo que el algoritmo exige, la API **falla al
arrancar** con un mensaje explícito en vez de levantar en un estado inseguro.

### Generar el par de llaves

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\n'
```

Una sola línea, lista para pegar en user-secrets o en una variable de entorno. Se acepta también el
PEM crudo, o el base64 del DER: las herramientas no se ponen de acuerdo (el `genpkey` de LibreSSL en
macOS escribe PKCS#8 en PEM pero PKCS#1 en DER), así que el cargador admite las cuatro formas.

Mínimo 2048 bits; una llave menor se rechaza al arrancar.

### Configurar

En desarrollo, fuera del repo:

```bash
cd src/AuthSystem.Api
dotnet user-secrets set "Jwt:PrivateKey" "<la llave generada>"
dotnet user-secrets list          # verificar
```

En despliegue, con la variable de entorno equivalente (el doble guion bajo separa secciones en .NET):

```bash
export Jwt__PrivateKey="<la llave generada>"
```

### Rotar sin downtime

La rotación no requiere tocar a los consumidores ni coordinar despliegues: publicas la llave nueva y
ellos la recogen del JWKS por su `kid`.

Para que además sea **sin corte**, durante la ventana de rotación se publican las dos llaves:

```bash
# 1. exportar la pública de la llave que sale
openssl pkey -pubout -in llave-actual.pem | base64 | tr -d '\n'   # -> Jwt__PreviousPublicKey

# 2. generar la nueva
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\n'  # -> Jwt__PrivateKey

# 3. desplegar con las dos. Pasados >15 min, quitar Jwt__PreviousPublicKey.
```

Durante esa ventana el JWKS expone ambas llaves, los tokens firmados con la saliente siguen validando
hasta expirar, y los consumidores que aún tengan el JWKS anterior en caché siguen funcionando. La
llave saliente solo se usa para **validar**: nunca vuelve a firmar.

Los refresh tokens son ajenos a todo esto: están hasheados en base de datos, no firmados.

### `Jwt:Secret` (HS256, en retirada)

La llave simétrica anterior sigue leyéndose **solo para validar** tokens emitidos antes del cambio a
RS256, mientras `Jwt:AcceptLegacyHs256` esté en `true`. Ya no se firma nada con ella.

Una vez que no pueda quedar ningún token HS256 dentro de su ventana de 15 minutos (en la práctica, al
día siguiente del despliegue), cierra la transición:

```jsonc
// appsettings.json
"Jwt": { "AcceptLegacyHs256": false }
```

y borra `Jwt:Secret` de user-secrets y del entorno. Hasta ese momento, cualquiera que tenga esa llave
puede emitir tokens que este servicio aceptará — que es justamente lo que la migración a RS256 viene
a cerrar.

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
| GET | `/api/applications` | Lista las aplicaciones registradas (rol `Admin`) |
| POST | `/api/applications` | Registra una aplicación consumidora con su audiencia (rol `Admin`) |
| POST | `/api/applications/{clientId}/deactivate` | Desactiva una aplicación (rol `Admin`) |
| GET | `/.well-known/jwks.json` | **Público.** Clave(s) pública(s) de firma, para que los consumidores validen |
| GET | `/.well-known/openid-configuration` | **Público.** Descubrimiento mínimo (`issuer`, `jwks_uri`) |

## Integrar una API consumidora

Este servicio es el único que emite tokens. Una API consumidora (por ejemplo `finance-api`) solo los **verifica**: no toca la base de datos de usuarios ni guarda contraseñas.

### Contrato del access token

Header:

```json
{ "alg": "RS256", "kid": "s8SWDobMqoed8cvZ8-S6ngOMbchKaty1sywz-uGODlk", "typ": "JWT" }
```

El `kid` identifica la llave del JWKS con la que verificar. Se deriva del thumbprint de la llave (RFC 7638), así que es estable y reproducible: eso es lo que permite publicar dos llaves a la vez y rotar sin coordinar despliegues.

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

1. **La firma**, con la clave pública que publica `/.well-known/jwks.json`.
2. **`iss` = `AuthSystem`**.
3. **`aud` = `AuthSystem.Clients`**.
4. **El algoritmo, fijado explícitamente a `RS256`.**

El punto 4 no es opcional. Si la librería acepta el algoritmo que venga en el header del token, un atacante puede cambiar `alg` a `none` (token sin firma) o firmar con HMAC usando la **clave pública como secreto** — y como ahora esa clave es, por diseño, pública, el ataque está al alcance de cualquiera. Son los **ataques de confusión de algoritmo**. Fijar la lista de algoritmos permitidos los cierra; este servicio los rechaza y el consumidor debe hacer lo mismo.

Este servicio valida la expiración con un margen (`ClockSkew`) de 30 segundos; conviene que el consumidor use un margen parecido en vez del default de 5 minutos de muchas librerías.

En Node/Express (`jsonwebtoken` + `jwks-rsa`):

```js
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const ROLE_CLAIM = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

const client = jwksClient({
  jwksUri: `${process.env.AUTH_SERVICE_URL}/.well-known/jwks.json`,
  cache: true,               // no golpear el auth en cada request
  cacheMaxAge: 3600_000,
  rateLimit: true,
});

// Resolver la llave por el kid del header: nunca probar llaves "a ver cuál pega".
const getKey = (header, cb) =>
  client.getSigningKey(header.kid, (err, key) =>
    cb(err, key && key.getPublicKey()));

function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization || "").split(" ");
  if (scheme !== "Bearer" || !token) return res.sendStatus(401);

  jwt.verify(token, getKey, {
    algorithms: ["RS256"],          // obligatorio: cierra la confusión de algoritmo
    issuer: "AuthSystem",
    audience: "AuthSystem.Clients",
    clockTolerance: 30,
  }, (err, payload) => {
    if (err) return res.sendStatus(401);
    const roles = [].concat(payload[ROLE_CLAIM] ?? []);   // string o array
    req.user = { id: payload.sub, email: payload.email, roles };
    next();
  });
}
```

> **Durante la migración**, si necesitas aceptar los dos algoritmos a la vez, pasa
> `algorithms: ["RS256", "HS256"]` **y resuelve la llave según `header.alg`**: la pública solo para
> `RS256`, el secreto HMAC solo para `HS256`. Si dejas que la librería pruebe ambas contra el mismo
> material, reabres exactamente el ataque que el punto 4 cierra. Quita `HS256` en cuanto puedas.

En otra API .NET basta con apuntar al issuer: `AddJwtBearer(o => { o.Authority = authUrl; o.Audience = "AuthSystem.Clients"; o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256]; })` — descubre el JWKS por `/.well-known/openid-configuration` y no hay que configurar llaves a mano.

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

## Varias aplicaciones consumidoras

Cada aplicación consumidora se registra una vez y recibe **su propia audiencia**. Un token emitido
para el CRM es rechazado por finance-api y viceversa: si la app menos cuidadosa filtra un token, ese
token no abre las demás.

### Registrar una aplicación

```bash
curl -X POST http://localhost:5073/api/applications \
  -H "Authorization: Bearer <token de un Admin>" \
  -H "Content-Type: application/json" \
  -d '{"clientId":"crm-app","audience":"crm.myorg.app","displayName":"CRM"}'
```

Se crean automáticamente sus roles `Admin` y `User`. El registro exige rol `Admin`: decidir qué
audiencias emite este servicio no es algo que pueda hacer un usuario cualquiera.

`POST /api/applications/{clientId}/deactivate` la desactiva — deja de emitir tokens y los existentes
fallan la validación de audiencia, sin borrar roles ni asignaciones.

### Pedir un token para una aplicación

```jsonc
POST /api/auth/login
{ "email": "...", "password": "...", "clientId": "crm-app" }   // -> aud: "crm.myorg.app"
```

**`clientId` es opcional.** Si se omite, se usa la aplicación `default`, cuya audiencia es
`AuthSystem.Clients` — exactamente la que validaban los consumidores anteriores, así que no hubo que
cambiar nada en ellos.

### Roles por aplicación

Un rol pertenece a una aplicación: puedes ser `Admin` en el CRM y `User` en finance. En la base de
datos se guardan cualificados (`crm-app:Admin`) porque Identity exige nombres de rol únicos, pero el
token lleva solo el nombre simple:

```jsonc
// token para crm-app          // token para default
"...claims/role": "Admin"      "...claims/role": "User"
```

El consumidor no ve el prefijo y no tiene que saber que existe.

### Añadir la aplicación número 100

No toca este repositorio. Se registra por API, las audiencias se recargan solas en todas las
instancias (caché de 60 s) y el consumidor nuevo solo necesita la URL del servicio para leer el JWKS.
No se reparte ningún secreto.

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
docker exec authsystem-db psql -U authsystem -d authsystem -c \
  'INSERT INTO "AspNetUserRoles" ("UserId", "RoleId")
   SELECT u."Id", r."Id" FROM "AspNetUsers" u, "AspNetRoles" r
   WHERE u."Email" = '"'"'test@example.com'"'"' AND r."Name" = '"'"'default:Admin'"'"';'

El nombre del rol va cualificado (`default:Admin`) porque los roles pertenecen a una aplicación.
```

## Escalado horizontal

El servicio **puede correr en varias instancias detrás de un balanceador**. Todo el estado compartido
vive en PostgreSQL:

- **Usuarios, roles, aplicaciones y refresh tokens**: en base de datos desde siempre.
- **Desafíos 2FA pendientes** (`MfaChallenges`): antes en `IMemoryCache`, lo que obligaba a una sola
  instancia — un `login` atendido por la instancia A y un `login/2fa` que cayera en la B fallaba con
  401. Ahora están en base de datos y los canjea cualquier instancia.
- El canje es **atómico y de un solo uso**: un `DELETE ... RETURNING` resuelve la lectura y el borrado
  en una sola sentencia, así que dos instancias compitiendo por el mismo `mfaToken` no pueden
  canjearlo las dos. Verificado con 20 intentos concurrentes: exactamente uno gana.
- **Las audiencias se recargan solas**: cada instancia mantiene un snapshot en memoria que refresca
  cada 60 s, así que registrar una aplicación se propaga sin reiniciar ni coordinar nada.

Lo único por instancia es ese snapshot de audiencias, y es una caché: reconstruirlo es una consulta.

Los desafíos pendientes caducan solos (TTL de 5 minutos) y quedan inutilizables aunque no se borren;
`DbMfaChallengeStore.RemoveExpiredAsync` limpia la tabla cuando se quiera programar.

## Estructura

```
src/AuthSystem.Api/
  Controllers/      AuthController, UsersController, ClientApplicationsController,
                     WellKnownController (JWKS)
  Data/              AppDbContext, DataSeeder, migraciones EF
  Dtos/              Contratos de request/response
  Models/            ApplicationUser, ApplicationRole, ClientApplication,
                     RefreshToken, MfaChallenge
  Options/           JwtOptions
  Services/          TokenService (JWT + refresh), JwtKeyProvider (llaves de firma + JWKS),
                     ClientApplicationService (registro de apps), DbMfaChallengeStore
```

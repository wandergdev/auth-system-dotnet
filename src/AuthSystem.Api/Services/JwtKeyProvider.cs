using System.Security.Cryptography;
using System.Text;
using AuthSystem.Api.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthSystem.Api.Services;

/// Owns the signing key material for the lifetime of the process.
///
/// Registered as a singleton: the RSA instance is expensive to build and is used on
/// every token issued, and RSA.SignData is thread-safe for concurrent readers.
public sealed class JwtKeyProvider : IJwtKeyProvider, IDisposable
{
    /// HS256 keys shorter than this are rejected: the algorithm is defined over a
    /// 256-bit key, and a shorter one silently weakens every token.
    public const int MinimumHmacKeyBytes = 32;

    /// Below 2048 bits RSA signatures are considered broken for new deployments.
    public const int MinimumRsaKeySizeBits = 2048;

    private readonly RSA? _rsa;
    private readonly RSA? _previousRsa;
    private readonly RsaSecurityKey? _previousRsaKey;

    public SigningCredentials SigningCredentials { get; }
    public IReadOnlyList<SecurityKey> ValidationKeys { get; }
    public IReadOnlyList<string> ValidAlgorithms { get; }

    private readonly RsaSecurityKey? _rsaKey;

    public JwtKeyProvider(IOptions<JwtOptions> options)
    {
        var jwt = options.Value;
        var algorithm = NormalizeAlgorithm(jwt.Algorithm);

        var validationKeys = new List<SecurityKey>();
        var validAlgorithms = new List<string>();

        if (algorithm == SecurityAlgorithms.RsaSha256)
        {
            _rsa = LoadRsaPrivateKey(jwt.PrivateKey);
            if (_rsa.KeySize < MinimumRsaKeySizeBits)
            {
                throw new InvalidOperationException(
                    $"Jwt:PrivateKey is a {_rsa.KeySize}-bit RSA key. RS256 requires at least " +
                    $"{MinimumRsaKeySizeBits} bits. Generate one with: " +
                    "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\\n'");
            }

            _rsaKey = new RsaSecurityKey(_rsa) { KeyId = ComputeRsaThumbprint(_rsa) };
            SigningCredentials = new SigningCredentials(_rsaKey, SecurityAlgorithms.RsaSha256);

            validationKeys.Add(_rsaKey);
            validAlgorithms.Add(SecurityAlgorithms.RsaSha256);

            // Rotation window: the outgoing public key keeps validating tokens it signed
            // and stays in the JWKS, so neither in-flight tokens nor consumers holding a
            // cached JWKS break while the new key propagates.
            if (!string.IsNullOrWhiteSpace(jwt.PreviousPublicKey))
            {
                _previousRsa = LoadRsaPublicKey(jwt.PreviousPublicKey);
                _previousRsaKey = new RsaSecurityKey(_previousRsa) { KeyId = ComputeRsaThumbprint(_previousRsa) };
                validationKeys.Add(_previousRsaKey);
            }

            // Transition window: tokens signed with the old symmetric key stay valid until
            // they expire, so a deploy does not log every current session out. Turn
            // Jwt:AcceptLegacyHs256 off once no HS256 token can still be in flight.
            if (jwt.AcceptLegacyHs256 && !string.IsNullOrWhiteSpace(jwt.Secret))
            {
                validationKeys.Add(BuildHmacKey(jwt.Secret));
                validAlgorithms.Add(SecurityAlgorithms.HmacSha256);
            }
        }
        else
        {
            var hmacKey = BuildHmacKey(jwt.Secret);
            SigningCredentials = new SigningCredentials(hmacKey, SecurityAlgorithms.HmacSha256);

            validationKeys.Add(hmacKey);
            validAlgorithms.Add(SecurityAlgorithms.HmacSha256);
        }

        ValidationKeys = validationKeys;
        ValidAlgorithms = validAlgorithms;
    }

    public JwksDocument? BuildJwks()
    {
        // Nothing to publish while signing with HS256: the key is symmetric, so exposing
        // it would hand every reader the ability to mint tokens.
        if (_rsaKey is null || _rsa is null)
        {
            return null;
        }

        var parameters = _rsa.ExportParameters(includePrivateParameters: false);
        var key = new JsonWebKeyDto(
            Kty: "RSA",
            Use: "sig",
            Alg: SecurityAlgorithms.RsaSha256,
            Kid: _rsaKey.KeyId,
            N: Base64UrlEncoder.Encode(parameters.Modulus!),
            E: Base64UrlEncoder.Encode(parameters.Exponent!));

        var keys = new List<JsonWebKeyDto> { key };

        if (_previousRsaKey is not null && _previousRsa is not null)
        {
            var previous = _previousRsa.ExportParameters(includePrivateParameters: false);
            keys.Add(new JsonWebKeyDto(
                Kty: "RSA", Use: "sig", Alg: SecurityAlgorithms.RsaSha256,
                Kid: _previousRsaKey.KeyId,
                N: Base64UrlEncoder.Encode(previous.Modulus!),
                E: Base64UrlEncoder.Encode(previous.Exponent!)));
        }

        return new JwksDocument(keys);
    }

    /// Accepts "RS256"/"HS256" in any casing, and the full URI form the IdentityModel
    /// constants use, so config stays readable.
    public static string NormalizeAlgorithm(string? algorithm)
    {
        var value = (algorithm ?? string.Empty).Trim();

        if (value.Equals("RS256", StringComparison.OrdinalIgnoreCase) ||
            value.Equals(SecurityAlgorithms.RsaSha256, StringComparison.OrdinalIgnoreCase) ||
            value.Equals(SecurityAlgorithms.RsaSha256Signature, StringComparison.OrdinalIgnoreCase))
        {
            return SecurityAlgorithms.RsaSha256;
        }

        if (value.Equals("HS256", StringComparison.OrdinalIgnoreCase) ||
            value.Equals(SecurityAlgorithms.HmacSha256, StringComparison.OrdinalIgnoreCase) ||
            value.Equals(SecurityAlgorithms.HmacSha256Signature, StringComparison.OrdinalIgnoreCase))
        {
            return SecurityAlgorithms.HmacSha256;
        }

        throw new InvalidOperationException(
            $"Jwt:Algorithm has an unsupported value '{algorithm}'. Use 'RS256' (recommended) or 'HS256'.");
    }

    private static SymmetricSecurityKey BuildHmacKey(string? secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new InvalidOperationException(
                "Jwt:Secret is not configured. The API refuses to start without a signing key. " +
                "Local development: run 'dotnet user-secrets set \"Jwt:Secret\" \"<key>\"' from src/AuthSystem.Api. " +
                "Deployment: set the Jwt__Secret environment variable. " +
                "Generate a key with: openssl rand -base64 48");
        }

        var bytes = Encoding.UTF8.GetBytes(secret);
        if (bytes.Length < MinimumHmacKeyBytes)
        {
            throw new InvalidOperationException(
                $"Jwt:Secret is too short: {bytes.Length} bytes. HS256 requires a key of at least " +
                $"{MinimumHmacKeyBytes} bytes (256 bits). Generate one with: openssl rand -base64 48");
        }

        return new SymmetricSecurityKey(bytes);
    }

    /// Reads the private key in any of the shapes openssl actually produces, because the
    /// tools disagree: LibreSSL's genpkey writes PKCS#8 as PEM but PKCS#1 as DER, while
    /// OpenSSL 3 writes PKCS#8 for both. Accepted here: a PEM block (PKCS#8 or PKCS#1),
    /// the base64 of such a PEM, or the base64 of raw DER in either format.
    ///
    /// Base64 on a single line is the shape to use in an environment variable: a PEM's
    /// newlines routinely get mangled in transit.
    private static RSA LoadRsaPrivateKey(string? material)
    {
        if (string.IsNullOrWhiteSpace(material))
        {
            throw new InvalidOperationException(
                "Jwt:PrivateKey is not configured, but Jwt:Algorithm is RS256. The API refuses to start " +
                "without a signing key. Local development: run " +
                "'dotnet user-secrets set \"Jwt:PrivateKey\" \"<base64>\"' from src/AuthSystem.Api. " +
                "Deployment: set the Jwt__PrivateKey environment variable. Generate a key with: " +
                "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\\n'");
        }

        var trimmed = material.Trim();
        var rsa = RSA.Create();

        try
        {
            if (TryGetPem(trimmed, out var pem))
            {
                // Handles both "BEGIN PRIVATE KEY" (PKCS#8) and "BEGIN RSA PRIVATE KEY" (PKCS#1).
                rsa.ImportFromPem(pem);
            }
            else
            {
                var der = Convert.FromBase64String(trimmed);
                try
                {
                    rsa.ImportPkcs8PrivateKey(der, out _);
                }
                catch (CryptographicException)
                {
                    rsa.ImportRSAPrivateKey(der, out _);
                }
            }
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            rsa.Dispose();
            throw new InvalidOperationException(
                "Jwt:PrivateKey could not be read. Expected an RSA private key as a PEM block " +
                "('-----BEGIN PRIVATE KEY-----'), or the base64 of that PEM, or the base64 of its DER " +
                "encoding. Generate one with: " +
                "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 | tr -d '\\n'",
                ex);
        }

        return rsa;
    }

    /// Loads the retiring key. Only the public half is needed: it validates old tokens
    /// but must never sign anything.
    private static RSA LoadRsaPublicKey(string material)
    {
        var trimmed = material.Trim();
        var rsa = RSA.Create();

        try
        {
            if (TryGetPem(trimmed, out var pem))
            {
                rsa.ImportFromPem(pem);
            }
            else
            {
                rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(trimmed), out _);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            rsa.Dispose();
            throw new InvalidOperationException(
                "Jwt:PreviousPublicKey could not be read. Expected an RSA public key as a PEM block " +
                "('-----BEGIN PUBLIC KEY-----'), or the base64 of that PEM, or of its DER encoding. " +
                "Export it from the retiring private key with: openssl pkey -pubout", ex);
        }

        return rsa;
    }

    /// Recognises a PEM block given directly, or one that was base64-encoded a second
    /// time to survive as a single-line environment variable.
    private static bool TryGetPem(string material, out string pem)
    {
        if (material.StartsWith("-----BEGIN", StringComparison.Ordinal))
        {
            pem = material;
            return true;
        }

        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(material));
            if (decoded.TrimStart().StartsWith("-----BEGIN", StringComparison.Ordinal))
            {
                pem = decoded;
                return true;
            }
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or DecoderFallbackException)
        {
            // Not base64, or not text: fall through and let the caller try raw DER.
        }

        pem = string.Empty;
        return false;
    }

    /// RFC 7638 JWK thumbprint: SHA-256 over the canonical JSON of the public key,
    /// with members ordered e, kty, n and no whitespace. Deriving the kid this way
    /// keeps it stable and reproducible from the key alone, so a consumer that caches
    /// the JWKS can tell two keys apart across a rotation.
    private static string ComputeRsaThumbprint(RSA rsa)
    {
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        var e = Base64UrlEncoder.Encode(parameters.Exponent!);
        var n = Base64UrlEncoder.Encode(parameters.Modulus!);

        var canonical = $"{{\"e\":\"{e}\",\"kty\":\"RSA\",\"n\":\"{n}\"}}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));

        return Base64UrlEncoder.Encode(hash);
    }

    public void Dispose()
    {
        _rsa?.Dispose();
        _previousRsa?.Dispose();
    }
}

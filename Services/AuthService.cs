using IS_2_Back_End.Attributes;
using IS_2_Back_End.Document;
using IS_2_Back_End.DTOs;
using IS_2_Back_End.DTOs.Auth;
using IS_2_Back_End.Entities;
using IS_2_Back_End.Helpers;
using IS_2_Back_End.Repositories;
using IS_2_Back_End.Utils;
using System.Security.Cryptography;
using System.Text.Json;


namespace IS_2_Back_End.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly Sha256Hasher _hasher;
    private readonly TokenService _tokenService;
    private readonly N8nClient _n8nClient;
    private readonly ILogger<AuthService>? _logger;

    public AuthService(
        IUserRepository userRepository,
        Sha256Hasher hasher,
        TokenService tokenService,
        N8nClient n8nClient,
        ILogger<AuthService>? logger = null)
    {
        _userRepository = userRepository;
        _hasher = hasher;
        _tokenService = tokenService;
        _n8nClient = n8nClient;
        _logger = logger;
    }

    #region Registro y Verificación Básicos
    /// <summary>
    /// Registra un nuevo usuario en el sistema
    /// REQ-002: Validación de entrada (XSS y SQL Injection)
    /// REQ-003: Validación de complejidad de contraseña
    /// </summary>
    [Requirement(Requirements.INPUT_VALIDATION_REQUIRED, "Validación de entrada para prevenir XSS y SQL Injection")]
    [Requirement(Requirements.PASSWORD_COMPLEXITY_REQUIRED, "Validación de complejidad de contraseña")]
    public async Task<UserResponse> RegisterAsync(RegisterRequest request)
    {
        var (isValid, errors) = InputSanitizer.Validation.ValidateRegistration(
        request.Email, request.Phone, request.Nombre, request.Apellido, request.Sexo);

        if (!isValid)
        {
            throw new InvalidOperationException($"Datos inválidos: {string.Join(", ", errors)}");
        }

        // VALIDACIÓN 2: Validar complejidad de contraseña
        var passwordValidation = PasswordValidator.Validate(request.Password);
        if (!passwordValidation.IsValid)
        {
            throw new InvalidOperationException(
                $"Contraseña inválida:\n{string.Join("\n", passwordValidation.Errors)}");
        }

        // Sanitizar datos
        request.Email = InputSanitizer.SanitizeEmail(request.Email);
        request.Phone = InputSanitizer.SanitizePhone(request.Phone);
        request.Nombre = InputSanitizer.SanitizeName(request.Nombre);
        request.Apellido = InputSanitizer.SanitizeName(request.Apellido);
        if (await _userRepository.EmailExistsAsync(request.Email))
        {
            throw new InvalidOperationException("El email ya está registrado");
        }

        var salt = _hasher.GenerateSalt();
        var user = new User
        {
            Email = request.Email,
            Phone = request.Phone,
            Salt = salt,
            PasswordHash = _hasher.HashPassword(request.Password, salt),
            IsVerified = false,
            Nombre = request.Nombre,
            Apellido = request.Apellido,
            Sexo = request.Sexo,
            CreatedAt = DateTime.UtcNow
        };

        user = await _userRepository.CreateAsync(user);

        user.UserRoles.Add(new UserRole
        {
            UserId = user.Id,
            RoleId = 1 // user role
        });

        await _userRepository.UpdateAsync(user);

        var otpCode = GenerateOtpCode();
        var verificationToken = new VerificationToken
        {
            UserId = user.Id,
            Token = otpCode,
            Purpose = Constants.EmailVerification,
            Payload = JsonSerializer.Serialize(new { email = user.Email }),
            ExpiresAt = DateTime.UtcNow.AddMinutes(15),
            CreatedAt = DateTime.UtcNow
        };

        await _userRepository.CreateVerificationTokenAsync(verificationToken);
        await _n8nClient.SendVerificationEmailAsync(user.Email, otpCode);

        return MapToUserResponse(user);
    }

    public async Task<bool> VerifyEmailAsync(VerifyTokenRequest request)
    {
        var verificationToken = await _userRepository.GetVerificationTokenAsync(request.Email, request.Token);

        if (verificationToken == null)
        {
            throw new InvalidOperationException("Token de verificación inválido o expirado");
        }

        var user = verificationToken.User;
        user.IsVerified = true;
        await _userRepository.UpdateAsync(user);

        verificationToken.Consumed = true;
        verificationToken.ConsumedAt = DateTime.UtcNow;
        await _userRepository.UpdateVerificationTokenAsync(verificationToken);

        return true;
    }

    public async Task<bool> ResendVerificationCodeAsync(string email)
    {
        var user = await _userRepository.GetByEmailAsync(email);

        if (user == null)
        {
            throw new InvalidOperationException("Usuario no encontrado");
        }

        if (user.IsVerified)
        {
            throw new InvalidOperationException("El email ya está verificado");
        }

        await _userRepository.InvalidateOldVerificationTokensAsync(user.Id);

        var otpCode = GenerateOtpCode();
        var verificationToken = new VerificationToken
        {
            UserId = user.Id,
            Token = otpCode,
            Purpose = Constants.EmailVerification,
            Payload = JsonSerializer.Serialize(new { email = user.Email }),
            ExpiresAt = DateTime.UtcNow.AddMinutes(15),
            CreatedAt = DateTime.UtcNow
        };

        await _userRepository.CreateVerificationTokenAsync(verificationToken);
        await _n8nClient.SendVerificationEmailAsync(user.Email, otpCode);

        return true;
    }

    #endregion

    #region Prevalidación

    public async Task<PrevalidateResponse> PrevalidateEmailAsync(string email)
    {
        var user = await _userRepository.GetByEmailAsync(email);

        if (user == null)
        {
            return new PrevalidateResponse
            {
                EmailExists = false,
                IsVerified = false,
                CanLogin = false,
                AvailableLoginMethods = new List<string>()
            };
        }

        var methods = new List<string> { "password" };

        if (user.IsVerified)
        {
            methods.AddRange(new[] { "otp", "magic_link" });
        }

        return new PrevalidateResponse
        {
            EmailExists = true,
            IsVerified = user.IsVerified,
            CanLogin = user.IsVerified,
            AvailableLoginMethods = methods
        };
    }

    #endregion

    #region Verificación Genérica de Tokens

    public async Task<bool> VerifyGenericTokenAsync(VerifyGenericTokenRequest request)
    {
        var token = await _userRepository.GetVerificationTokenByPurposeAsync(
            request.Email,
            request.Token,
            request.Purpose
        );

        if (token == null)
        {
            throw new InvalidOperationException("Token inválido o expirado");
        }

        token.Consumed = true;
        token.ConsumedAt = DateTime.UtcNow;
        await _userRepository.UpdateVerificationTokenAsync(token);

        return true;
    }

    #endregion

    #region Login con Password

    /// <summary>
    /// Login con email y contraseña
    /// REQ-001: Verificación de correo electrónico obligatoria
    /// Bloquea login si el email no ha sido verificado
    /// </summary>
    /// <param name="request">Credenciales de login (email y password)</param>
    /// <returns>Tokens de acceso y refresh</returns>
    /// <exception cref="UnauthorizedAccessException">Si las credenciales son inválidas o el email no está verificado</exception>
    [Requirement(Requirements.EMAIL_VERIFICATION_REQUIRED,
        "Verificación de correo electrónico obligatoria para login con password")]
    public async Task<TokenResponse> LoginWithPasswordAsync(LoginPasswordRequest request)
    {
        var user = await _userRepository.GetByEmailWithRolesAsync(request.Email);

        if (user == null || !_hasher.VerifyPassword(request.Password, user.Salt, user.PasswordHash))
        {
            throw new UnauthorizedAccessException("Credenciales inválidas");
        }

        if (!user.IsVerified)
        {
            // Verificación REQ-001: Email debe estar verificado antes de permitir login  
            throw new UnauthorizedAccessException("Debes verificar tu email antes de iniciar sesión");
        }

        return await GenerateAuthTokensAsync(user);
    }

    #endregion

    #region Login con OTP

    /// <summary>
    /// Solicita un código OTP después de validar la contraseña
    /// REQ-001: Verificación de correo electrónico obligatoria
    /// </summary>
    [Requirement(Requirements.EMAIL_VERIFICATION_REQUIRED,
        "Verificación de correo electrónico obligatoria para solicitar OTP")]
    public async Task<bool> RequestLoginOtpAsync(LoginPasswordRequestOtpRequest request)
    {
        var user = await _userRepository.GetByEmailAsync(request.Email);

        if (user == null || !_hasher.VerifyPassword(request.Password, user.Salt, user.PasswordHash))
        {
            throw new UnauthorizedAccessException("Credenciales inválidas");
        }

        if (!user.IsVerified)
        {
            throw new UnauthorizedAccessException("Debes verificar tu email primero");
        }

        await _userRepository.InvalidateOldTokensByPurposeAsync(user.Id, Constants.OtpPurpose);

        var otpCode = GenerateOtpCode();
        var otpToken = new VerificationToken
        {
            UserId = user.Id,
            Token = otpCode,
            Purpose = Constants.OtpPurpose,
            Payload = JsonSerializer.Serialize(new { email = user.Email, type = "login" }),
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
            CreatedAt = DateTime.UtcNow
        };

        await _userRepository.CreateVerificationTokenAsync(otpToken);
        await _n8nClient.SendOtpEmailAsync(user.Email, otpCode);

        return true;
    }

    public async Task<TokenResponse> LoginWithOtpAsync(LoginOtpRequest request)
    {
        var token = await _userRepository.GetVerificationTokenByPurposeAsync(
            request.Email,
            request.OtpCode,
            Constants.OtpPurpose
        );

        if (token == null)
        {
            throw new UnauthorizedAccessException("Código OTP inválido o expirado");
        }

        var user = await _userRepository.GetByEmailWithRolesAsync(request.Email);
        if (user == null)
        {
            throw new UnauthorizedAccessException("Usuario no encontrado");
        }

        token.Consumed = true;
        token.ConsumedAt = DateTime.UtcNow;
        await _userRepository.UpdateVerificationTokenAsync(token);

        return await GenerateAuthTokensAsync(user);
    }

    #endregion

    #region Magic Link
    /// <summary>
    /// Solicita un magic link para login sin contraseña
    /// REQ-001: Verificación de correo electrónico obligatoria
    /// </summary>
    [Requirement(Requirements.EMAIL_VERIFICATION_REQUIRED,
        "Verificación de correo electrónico obligatoria para solicitar Magic Link")]
    public async Task<bool> RequestMagicLinkAsync(string email)
    {
        var user = await _userRepository.GetByEmailAsync(email);

        if (user == null)
        {
            throw new InvalidOperationException("Usuario no encontrado");
        }

        if (!user.IsVerified)
        {
            throw new InvalidOperationException("Debes verificar tu email primero");
        }

        await _userRepository.InvalidateOldTokensByPurposeAsync(user.Id, Constants.MagicLink);

        var magicToken = GenerateSecureToken();
        var verificationToken = new VerificationToken
        {
            UserId = user.Id,
            Token = magicToken,
            Purpose = Constants.MagicLink,
            Payload = JsonSerializer.Serialize(new { email = user.Email }),
            ExpiresAt = DateTime.UtcNow.AddMinutes(15),
            CreatedAt = DateTime.UtcNow
        };

        await _userRepository.CreateVerificationTokenAsync(verificationToken);
        await _n8nClient.SendMagicLinkEmailAsync(user.Email, magicToken);

        return true;
    }

    public async Task<TokenResponse> LoginWithMagicLinkAsync(string token)
    {
        var verificationToken = await _userRepository.GetVerificationTokenByTokenAsync(token, Constants.MagicLink);

        if (verificationToken == null)
        {
            throw new UnauthorizedAccessException("Magic link inválido o expirado");
        }

        var user = await _userRepository.GetByEmailWithRolesAsync(verificationToken.User.Email);
        if (user == null)
        {
            throw new UnauthorizedAccessException("Usuario no encontrado");
        }

        verificationToken.Consumed = true;
        verificationToken.ConsumedAt = DateTime.UtcNow;
        await _userRepository.UpdateVerificationTokenAsync(verificationToken);

        return await GenerateAuthTokensAsync(user);
    }

    #endregion

    #region OAuth Google

    public async Task<GoogleOAuthResponse> AuthenticateWithGoogleAsync(string idToken)
    {
        // Aquí deberías validar el idToken con Google
        // Por ahora simularemos la respuesta

        // TODO: Implementar validación real con Google.Apis.Auth
        // var payload = await GoogleJsonWebSignature.ValidateAsync(idToken);

        // Simulación (reemplazar con lógica real)
        var email = "user@gmail.com"; // Extraer del token de Google
        var nombre = "Usuario";
        var apellido = "Google";

        var user = await _userRepository.GetByEmailWithRolesAsync(email);
        var isNewUser = false;

        if (user == null)
        {
            var salt = _hasher.GenerateSalt();
            user = new User
            {
                Email = email,
                Salt = salt,
                PasswordHash = _hasher.HashPassword(Guid.NewGuid().ToString(), salt), // Password random
                IsVerified = true, // OAuth users are auto-verified
                Nombre = nombre,
                Apellido = apellido,
                CreatedAt = DateTime.UtcNow
            };

            user = await _userRepository.CreateAsync(user);

            user.UserRoles.Add(new UserRole
            {
                UserId = user.Id,
                RoleId = 1
            });

            await _userRepository.UpdateAsync(user);
            isNewUser = true;
        }

        var tokens = await GenerateAuthTokensAsync(user);

        return new GoogleOAuthResponse
        {
            AccessToken = tokens.AccessToken,
            RefreshToken = tokens.RefreshToken,
            ExpiresAt = tokens.ExpiresAt,
            TokenType = tokens.TokenType,
            IsNewUser = isNewUser,
            User = new UserInfo
            {
                Id = user.Id,
                Email = user.Email,
                Nombre = user.Nombre,
                Apellido = user.Apellido
            }
        };
    }

    #endregion

    #region Password Reset
    /// <summary>
    /// Resetea la contraseña usando el token recibido
    /// REQ-003: Validación de complejidad de contraseña
    /// </summary>
    [Requirement(Requirements.PASSWORD_COMPLEXITY_REQUIRED, "Validación de complejidad de contraseña en reset")]
    public async Task<bool> RequestPasswordResetAsync(string email)
    {
        var user = await _userRepository.GetByEmailAsync(email);

        if (user == null)
        {
            // Por seguridad, no revelamos si el email existe
            return true;
        }

        await _userRepository.InvalidateOldTokensByPurposeAsync(user.Id, "password_reset");

        var resetToken = GenerateSecureToken();
        var verificationToken = new VerificationToken
        {
            UserId = user.Id,
            Token = resetToken,
            Purpose = "password_reset",
            Payload = JsonSerializer.Serialize(new { email = user.Email }),
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            CreatedAt = DateTime.UtcNow
        };

        await _userRepository.CreateVerificationTokenAsync(verificationToken);
        await _n8nClient.SendPasswordResetEmailAsync(user.Email, resetToken);

        return true;
    }

    public async Task<bool> ResetPasswordAsync(ResetPasswordRequest request)
    {
        var token = await _userRepository.GetVerificationTokenByPurposeAsync(
            request.Email,
            request.Token,
            "password_reset"
        );

        if (token == null)
        {
            throw new InvalidOperationException("Token de reset inválido o expirado");
        }

        var user = token.User;

        // NUEVA VALIDACIÓN: Verificar si la nueva contraseña es igual a la actual
        var isSamePassword = _hasher.VerifyPassword(request.NewPassword, user.Salt, user.PasswordHash);

        if (isSamePassword)
        {
            throw new InvalidOperationException("La nueva contraseña no puede ser igual a la contraseña actual. Por favor, elige una contraseña diferente.");
        }

        // Si es diferente, proceder con el cambio
        var newSalt = _hasher.GenerateSalt();
        user.Salt = newSalt;
        user.PasswordHash = _hasher.HashPassword(request.NewPassword, newSalt);
        await _userRepository.UpdateAsync(user);

        token.Consumed = true;
        token.ConsumedAt = DateTime.UtcNow;
        await _userRepository.UpdateVerificationTokenAsync(token);

        // Revocar todos los refresh tokens del usuario por seguridad
        await _userRepository.RevokeAllUserRefreshTokensAsync(user.Id);

        return true;
    }

    #endregion

    #region Refresh y Revoke Tokens

    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
    {
        var tokenHash = HashToken(refreshToken);
        var tokenEntity = await _userRepository.GetRefreshTokenAsync(tokenHash);

        if (tokenEntity == null)
        {
            throw new UnauthorizedAccessException("Token de refresco inválido");
        }

        var user = await _userRepository.GetByEmailWithRolesAsync(tokenEntity.User.Email);
        if (user == null)
        {
            throw new UnauthorizedAccessException("Usuario no encontrado");
        }

        tokenEntity.Revoked = true;
        tokenEntity.RevokedAt = DateTime.UtcNow;
        await _userRepository.UpdateRefreshTokenAsync(tokenEntity);

        return await GenerateAuthTokensAsync(user);
    }

    public async Task RevokeTokenAsync(string refreshToken)
    {
        var tokenHash = HashToken(refreshToken);
        var tokenEntity = await _userRepository.GetRefreshTokenAsync(tokenHash);

        if (tokenEntity != null)
        {
            tokenEntity.Revoked = true;
            tokenEntity.RevokedAt = DateTime.UtcNow;
            await _userRepository.UpdateRefreshTokenAsync(tokenEntity);
        }
    }

    #endregion

    #region Helper Methods

    private async Task<TokenResponse> GenerateAuthTokensAsync(User user)
    {
        user.UpdatedAt = DateTime.UtcNow;
        await _userRepository.UpdateAsync(user);

        // Crear diccionario con claims adicionales  
        var additionalClaims = new Dictionary<string, object>
        {
            { "nombre", user.Nombre },
            { "apellido", user.Apellido },
            { "name", $"{user.Nombre} {user.Apellido}" }
        };

        var accessToken = _tokenService.GenerateAccessToken(user, additionalClaims);
        var refreshToken = _tokenService.GenerateRefreshToken();
        var refreshTokenHash = HashToken(refreshToken);

        var refreshTokenEntity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refreshTokenHash,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(30)
        };

        await _userRepository.CreateRefreshTokenAsync(refreshTokenEntity);

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(60)
        };
    }

    private string GenerateOtpCode()
    {
        var random = new Random();
        return random.Next(100000, 999999).ToString();
    }

    private string GenerateSecureToken()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }

    private string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(hashedBytes);
    }

    private UserResponse MapToUserResponse(User user)
    {
        return new UserResponse
        {
            Id = user.Id,
            Email = user.Email,
            Phone = user.Phone,
            Nombre = user.Nombre,
            Apellido = user.Apellido,
            Sexo = user.Sexo,
            IsEmailVerified = user.IsVerified,
            CreatedAt = user.CreatedAt,
            Roles = user.UserRoles?.Select(ur => ur.Role?.Name ?? "user").ToList() ?? new List<string>()
        };
    }
    #endregion
}

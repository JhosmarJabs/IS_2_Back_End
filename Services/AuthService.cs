using System.Security.Cryptography;
using IS_2_Back_End.DTOs;
using IS_2_Back_End.DTOs.Auth;
using IS_2_Back_End.Entities;
using IS_2_Back_End.Helpers;
using IS_2_Back_End.Repositories;


namespace IS_2_Back_End.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly Sha256Hasher _hasher;
    private readonly TokenService _tokenService;
    private readonly N8nClient _n8nClient;

    public AuthService(
        IUserRepository userRepository,
        Sha256Hasher hasher,
        TokenService tokenService,
        N8nClient n8nClient)
    {
        _userRepository = userRepository;
        _hasher = hasher;
        _tokenService = tokenService;
        _n8nClient = n8nClient;
    }

    public async Task<UserResponse> RegisterAsync(RegisterRequest request)
    {
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

        // Asignar rol de usuario por defecto
        user.UserRoles.Add(new UserRole
        {
            UserId = user.Id,
            RoleId = 1 // user role
        });

        await _userRepository.UpdateAsync(user);

        // Generar código OTP
        var otpCode = GenerateOtpCode();
        var verificationToken = new VerificationToken
        {
            UserId = user.Id,
            Token = otpCode,
            Purpose = "email_verification",
            Payload = $"{{\"email\":\"{user.Email}\"}}",
            ExpiresAt = DateTime.UtcNow.AddMinutes(15),
            CreatedAt = DateTime.UtcNow
        };

        await _userRepository.CreateVerificationTokenAsync(verificationToken);
        await _n8nClient.SendVerificationEmailAsync(user.Email, otpCode);

        return MapToUserResponse(user);
    }

    public async Task<TokenResponse> LoginAsync(LoginRequest request)
    {
        var user = await _userRepository.GetByEmailWithRolesAsync(request.Email);

        if (user == null || !_hasher.VerifyPassword(request.Password, user.Salt, user.PasswordHash))
        {
            throw new UnauthorizedAccessException("Credenciales inválidas");
        }

        if (!user.IsVerified)
        {
            throw new UnauthorizedAccessException("Debes verificar tu email antes de iniciar sesión");
        }

        user.UpdatedAt = DateTime.UtcNow;
        await _userRepository.UpdateAsync(user);

        var accessToken = _tokenService.GenerateAccessToken(user);
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

        var newAccessToken = _tokenService.GenerateAccessToken(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken();
        var newRefreshTokenHash = HashToken(newRefreshToken);

        tokenEntity.Revoked = true;
        tokenEntity.RevokedAt = DateTime.UtcNow;
        await _userRepository.UpdateRefreshTokenAsync(tokenEntity);

        var newRefreshTokenEntity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = newRefreshTokenHash,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(30)
        };

        await _userRepository.CreateRefreshTokenAsync(newRefreshTokenEntity);

        return new TokenResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(60)
        };
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
            Purpose = "email_verification",
            Payload = $"{{\"email\":\"{user.Email}\"}}",
            ExpiresAt = DateTime.UtcNow.AddMinutes(15),
            CreatedAt = DateTime.UtcNow
        };

        await _userRepository.CreateVerificationTokenAsync(verificationToken);
        await _n8nClient.SendVerificationEmailAsync(user.Email, otpCode);

        return true;
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

    private string GenerateOtpCode()
    {
        var random = new Random();
        return random.Next(100000, 999999).ToString();
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
            Nombre = user.Nombre, // Usamos phone ya que no hay firstName
            Apellido = user.Apellido,
            Sexo = user.Sexo,
            IsEmailVerified = user.IsVerified,
            CreatedAt = user.CreatedAt,
            Roles = user.UserRoles.Select(ur => ur.Role.Name).ToList()
        };
    }
}
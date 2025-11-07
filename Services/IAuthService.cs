using IS_2_Back_End.DTOs;
using IS_2_Back_End.DTOs.Auth;

namespace IS_2_Back_End.Services;

public interface IAuthService
{
    Task<UserResponse> RegisterAsync(RegisterRequest request);
    Task<TokenResponse> LoginAsync(LoginRequest request);
    Task<bool> VerifyEmailAsync(VerifyTokenRequest request);
    Task<TokenResponse> RefreshTokenAsync(string refreshToken);
    Task<bool> ResendVerificationCodeAsync(string email);
    Task RevokeTokenAsync(string refreshToken);
}

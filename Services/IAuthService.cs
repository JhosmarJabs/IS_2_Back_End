using IS_2_Back_End.DTOs;
using IS_2_Back_End.DTOs.Auth;

namespace IS_2_Back_End.Services;

public interface IAuthService
{
    // Registro y Verificación
    Task<UserResponse> RegisterAsync(RegisterRequest request);
    Task<bool> VerifyEmailAsync(VerifyTokenRequest request);
    Task<bool> ResendVerificationCodeAsync(string email);

    // Prevalidación
    Task<PrevalidateResponse> PrevalidateEmailAsync(string email);

    // Verificación Genérica
    Task<bool> VerifyGenericTokenAsync(VerifyGenericTokenRequest request);

    // Login con Password
    Task<TokenResponse> LoginAsync(LoginRequest request);
    Task<TokenResponse> LoginWithPasswordAsync(LoginPasswordRequest request);

    // Login con OTP
    Task<bool> RequestLoginOtpAsync(LoginPasswordRequestOtpRequest request);
    Task<TokenResponse> LoginWithOtpAsync(LoginOtpRequest request);

    // Magic Link
    Task<bool> RequestMagicLinkAsync(string email);
    Task<TokenResponse> LoginWithMagicLinkAsync(string token);

    // OAuth Google
    Task<GoogleOAuthResponse> AuthenticateWithGoogleAsync(string idToken);

    // Password Reset
    Task<bool> RequestPasswordResetAsync(string email);
    Task<bool> ResetPasswordAsync(ResetPasswordRequest request);

    // Token Management
    Task<TokenResponse> RefreshTokenAsync(string refreshToken);
    Task RevokeTokenAsync(string refreshToken);
}
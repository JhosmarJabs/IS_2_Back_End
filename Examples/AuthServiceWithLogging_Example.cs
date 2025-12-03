using IS_2_Back_End.Helpers;
using IS_2_Back_End.DTOs.Auth;
using IS_2_Back_End.Entities;
using IS_2_Back_End.Repositories;

namespace IS_2_Back_End.Services;

/// <summary>
/// EJEMPLO: AuthService con logging detallado
/// Copia este patrón en tus servicios existentes
/// </summary>
public class AuthServiceWithLogging
{
    private readonly IUserRepository _userRepository;
    private readonly Sha256Hasher _hasher;
    private readonly IDetailedLogger _detailedLogger;

    public AuthServiceWithLogging(
        IUserRepository userRepository,
        Sha256Hasher hasher,
        IDetailedLogger detailedLogger)
    {
        _userRepository = userRepository;
        _hasher = hasher;
        _detailedLogger = detailedLogger;
    }

    /// <summary>
    /// EJEMPLO 1: Login con logging manual
    /// </summary>
    public async Task<TokenResponse> LoginWithPasswordAsync(LoginPasswordRequest request)
    {
        // Usar el helper para logging automático
        return await _detailedLogger.ExecuteWithLoggingAsync(
            className: nameof(AuthServiceWithLogging),
            methodName: nameof(LoginWithPasswordAsync),
            operation: async () =>
            {
                // Tu lógica existente aquí
                _detailedLogger.LogBusinessLogic("Buscando usuario por email", new { email = request.Email });

                var user = await _userRepository.GetByEmailWithRolesAsync(request.Email);

                if (user == null)
                {
                    _detailedLogger.LogBusinessLogic("Usuario no encontrado");
                    throw new UnauthorizedAccessException("Credenciales inválidas");
                }

                _detailedLogger.LogBusinessLogic("Verificando contraseña");

                if (!_hasher.VerifyPassword(request.Password, user.Salt, user.PasswordHash))
                {
                    _detailedLogger.LogBusinessLogic("Contraseña incorrecta");
                    throw new UnauthorizedAccessException("Credenciales inválidas");
                }

                if (!user.IsVerified)
                {
                    _detailedLogger.LogBusinessLogic("Email no verificado", new { userId = user.Id });
                    throw new UnauthorizedAccessException("Debes verificar tu email antes de iniciar sesión");
                }

                _detailedLogger.LogBusinessLogic("Login exitoso", new { userId = user.Id, email = user.Email });

                // Generar tokens (tu lógica existente)
                return new TokenResponse
                {
                    AccessToken = "example-token",
                    RefreshToken = "example-refresh",
                    ExpiresAt = DateTime.UtcNow.AddMinutes(60)
                };
            },
            parameters: new { email = request.Email }
        );
    }

    /// <summary>
    /// EJEMPLO 2: Método con logging paso a paso
    /// </summary>
    public async Task<bool> RegisterAsync(RegisterRequest request)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            _detailedLogger.LogMethodEntry(nameof(AuthServiceWithLogging), nameof(RegisterAsync),
                new { email = request.Email });

            // Paso 1: Validar email duplicado
            _detailedLogger.LogBusinessLogic("Verificando si email existe", new { email = request.Email });
            var exists = await _userRepository.EmailExistsAsync(request.Email);

            if (exists)
            {
                _detailedLogger.LogBusinessLogic("Email ya registrado");
                throw new InvalidOperationException("El email ya está registrado");
            }

            // Paso 2: Crear usuario
            _detailedLogger.LogBusinessLogic("Creando nuevo usuario");
            var salt = _hasher.GenerateSalt();
            var user = new User
            {
                Email = request.Email,
                Salt = salt,
                PasswordHash = _hasher.HashPassword(request.Password, salt),
                IsVerified = false
            };

            await _userRepository.CreateAsync(user);

            // Paso 3: Enviar email de verificación
            _detailedLogger.LogBusinessLogic("Enviando email de verificación", new { userId = user.Id });
            // ... lógica de envío de email

            stopwatch.Stop();
            _detailedLogger.LogMethodExit(nameof(AuthServiceWithLogging), nameof(RegisterAsync),
                stopwatch.ElapsedMilliseconds);

            return true;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _detailedLogger.LogMethodError(nameof(AuthServiceWithLogging), nameof(RegisterAsync),
                ex, stopwatch.ElapsedMilliseconds);
            throw;
        }
    }
}
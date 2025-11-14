using System.Text;
using System.Text.Json;


namespace IS_2_Back_End.Helpers;

public class N8nClient
{
    private readonly HttpClient _httpClient;
    private readonly string _webhookUrl;

    public N8nClient(HttpClient httpClient, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _webhookUrl = configuration["N8nSettings:WebhookUrl"]
            ?? throw new InvalidOperationException("N8n webhook URL not configured");
    }

    public async Task SendVerificationEmailAsync(string email, string verificationCode)
    {
        await SendEmailAsync(email, "email_verification", new
        {
            verificationCode,
            subject = "Verifica tu email",
            message = $"Tu código de verificación es: {verificationCode}"
        });
    }

    public async Task SendOtpEmailAsync(string email, string otpCode)
    {
        await SendEmailAsync(email, "otp_login", new
        {
            otpCode,
            subject = "Código OTP para iniciar sesión",
            message = $"Tu código OTP es: {otpCode}. Válido por 10 minutos."
        });
    }

    public async Task SendMagicLinkEmailAsync(string email, string magicToken)
    {
        var magicLink = $"https://is-2-front-end.vercel.app/auth/magic?token={magicToken}";

        await SendEmailAsync(email, "magic_link", new
        {
            magicLink,
            subject = "Tu enlace mágico de acceso",
            message = $"Haz clic en este enlace para iniciar sesión: {magicLink}"
        });
    }

    public async Task SendPasswordResetEmailAsync(string email, string resetToken)
    {
        var resetLink = $"https://is-2-front-end.vercel.app/auth/reset?token={resetToken}";

        await SendEmailAsync(email, "password_reset", new
        {
            resetToken,
            resetLink,
            subject = "Recuperación de contraseña",
            message = $"Para restablecer tu contraseña, haz clic aquí: {resetLink}"
        });
    }

    private async Task SendEmailAsync(string email, string type, object data)
    {
        var payload = new
        {
            email,
            type,
            data,
            timestamp = DateTime.UtcNow
        };

        var jsonContent = new StringContent(
            JsonSerializer.Serialize(payload),
            Encoding.UTF8,
            "application/json"
        );

        try
        {
            var response = await _httpClient.PostAsync(_webhookUrl, jsonContent);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Error al enviar email ({type}): {response.StatusCode} - {error}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error al enviar email ({type}): {ex.Message}");
        }
    }
}

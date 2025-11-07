using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;

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
        var payload = new
        {
            email = email,
            verificationCode = verificationCode,
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
                throw new HttpRequestException(
                    $"Error al enviar email de verificación: {response.StatusCode} - {error}");
            }
        }
        catch (Exception ex)
        {
            // Log el error pero no fallar el registro
            Console.WriteLine($"Error al enviar email: {ex.Message}");
            // Puedes implementar un sistema de retry o queue aquí
        }
    }

    public async Task SendPasswordResetEmailAsync(string email, string resetToken)
    {
        var payload = new
        {
            email = email,
            resetToken = resetToken,
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
            response.EnsureSuccessStatusCode();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error al enviar email de reset: {ex.Message}");
        }
    }
}
using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;
using System.Text.Unicode;

namespace IS_2_Back_End.Helpers;

public class N8nClient
{
    private readonly HttpClient _httpClient;
    private readonly string _webhookUrl;
    private readonly string _url = "https://is-2-front-end.vercel.app/#/auth";

    public N8nClient(HttpClient httpClient, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _webhookUrl = configuration["N8nSettings:WebhookUrl"]
            ?? throw new InvalidOperationException("N8n webhook URL not configured");
    }

    private string GetTemplateHtml(string type, object data)
    {
        // Plantilla base moderna con diseño mejorado
        var baseTemplate = @"
<!DOCTYPE html>
<html lang=""es"">
<head>
  <meta charset=""UTF-8"">
  <meta name=""color-scheme"" content=""light dark"">
  <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
  <title>{{subject}}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      padding: 40px 20px;
      min-height: 100vh;
    }
    
    .email-wrapper {
      max-width: 600px;
      margin: 0 auto;
    }
    
    .container {
      background: #ffffff;
      border-radius: 24px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      overflow: hidden;
      animation: slideIn 0.5s ease-out;
    }
    
    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(-20px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      padding: 40px 30px;
      text-align: center;
      position: relative;
      overflow: hidden;
    }
    
    .header::before {
      content: '';
      position: absolute;
      top: -50%;
      left: -50%;
      width: 200%;
      height: 200%;
      background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
      animation: pulse 3s ease-in-out infinite;
    }
    
    @keyframes pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.1); }
    }
    
    .icon-container {
      position: relative;
      display: inline-block;
      background: rgba(255, 255, 255, 0.2);
      border-radius: 50%;
      width: 80px;
      height: 80px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 20px;
      backdrop-filter: blur(10px);
    }
    
    .icon {
      font-size: 40px;
      filter: drop-shadow(0 2px 4px rgba(0,0,0,0.2));
    }
    
    .header h1 {
      color: #ffffff;
      font-size: 28px;
      font-weight: 700;
      margin: 0;
      letter-spacing: -0.5px;
      position: relative;
    }
    
    .content {
      padding: 40px 30px;
      color: #2d3748;
      line-height: 1.7;
    }
    
    .content p {
      margin-bottom: 16px;
      font-size: 16px;
      color: #4a5568;
    }
    
    .content p:first-child {
      font-size: 18px;
      color: #2d3748;
      font-weight: 600;
    }
    
    .code-container {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      border-radius: 16px;
      padding: 24px;
      text-align: center;
      margin: 28px 0;
      box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
    }
    
    .code {
      font-size: 36px;
      font-weight: 800;
      color: #ffffff;
      letter-spacing: 8px;
      font-family: 'Courier New', monospace;
      text-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
      display: block;
    }
    
    .code-label {
      font-size: 12px;
      color: rgba(255, 255, 255, 0.8);
      text-transform: uppercase;
      letter-spacing: 2px;
      margin-top: 8px;
      font-weight: 600;
    }
    
    .cta {
      display: inline-block;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: #ffffff;
      text-decoration: none;
      padding: 16px 40px;
      border-radius: 12px;
      font-weight: 700;
      font-size: 16px;
      margin: 20px 0;
      box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
      transition: all 0.3s ease;
      letter-spacing: 0.5px;
    }
    
    .cta:hover {
      transform: translateY(-2px);
      box-shadow: 0 15px 40px rgba(102, 126, 234, 0.5);
    }
    
    .warning-box {
      background: #fff5e6;
      border-left: 4px solid #f59e0b;
      padding: 16px 20px;
      border-radius: 8px;
      margin: 24px 0;
    }
    
    .warning-box p {
      color: #92400e;
      font-size: 14px;
      margin: 0;
    }
    
    .info-box {
      background: #e0e7ff;
      border-left: 4px solid #667eea;
      padding: 16px 20px;
      border-radius: 8px;
      margin: 24px 0;
    }
    
    .info-box p {
      color: #3730a3;
      font-size: 14px;
      margin: 0;
    }
    
    .divider {
      height: 1px;
      background: linear-gradient(to right, transparent, #e2e8f0, transparent);
      margin: 30px 0;
    }
    
    .footer {
      background: #f7fafc;
      padding: 30px;
      text-align: center;
      border-top: 1px solid #e2e8f0;
    }
    
    .footer p {
      color: #718096;
      font-size: 14px;
      margin: 8px 0;
    }
    
    .footer-brand {
      color: #667eea;
      font-weight: 700;
      font-size: 16px;
      margin-bottom: 12px;
    }
    
    .footer-links {
      margin-top: 16px;
    }
    
    .footer-links a {
      color: #667eea;
      text-decoration: none;
      margin: 0 12px;
      font-size: 13px;
      font-weight: 500;
    }
    
    .social-icons {
      margin-top: 20px;
    }
    
    .social-icons span {
      display: inline-block;
      margin: 0 8px;
      font-size: 20px;
      opacity: 0.7;
    }
    
    @media only screen and (max-width: 600px) {
      body { padding: 20px 10px; }
      .header { padding: 30px 20px; }
      .header h1 { font-size: 24px; }
      .content { padding: 30px 20px; }
      .code { font-size: 28px; letter-spacing: 6px; }
      .footer { padding: 20px; }
    }
  </style>
</head>
<body>
  <div class=""email-wrapper"">
    <div class=""container"">
      <div class=""header"">
        <div class=""icon-container"">
          <span class=""icon"">{{icon}}</span>
        </div>
        <h1>{{subject}}</h1>
      </div>
      <div class=""content"">
        {{content}}
      </div>
      <div class=""footer"">
        <div class=""footer-brand"">🔒 Floreria Bautista</div>
        <p>Sistema de Autenticación Segura</p>
        <div class=""divider"" style=""margin: 20px 0;""></div>
        <p>Si tienes alguna duda, responde a este correo o contacta a soporte.</p>
        <div class=""footer-links"">
          <a href=""#"">Ayuda</a>
          <a href=""#"">Política de Privacidad</a>
          <a href=""#"">Términos de Uso</a>
        </div>
        <p style=""margin-top: 20px; color: #a0aec0; font-size: 12px;"">&copy; 2025 Floreria Bautista. Todos los derechos reservados.</p>
      </div>
    </div>
  </div>
</body>
</html>";

        // Contenidos específicos mejorados por tipo
        string specificContent = type switch
        {
            "email_verification" => $@"
                <p>¡Hola! 👋</p>
                <p>Gracias por registrarte en Floreria Bautista. Para completar tu registro y activar tu cuenta, necesitamos verificar tu dirección de correo electrónico.</p>
                <div class=""code-container"">
                  <span class=""code"">{((dynamic)data).verificationCode}</span>
                  <div class=""code-label"">Código de Verificación</div>
                </div>
                <div class=""info-box"">
                  <p>⏱️ <strong>Este código es válido por 15 minutos.</strong> Por seguridad, el código expirará automáticamente.</p>
                </div>
                <p>Si no solicitaste esta verificación, puedes ignorar este correo de forma segura.</p>",

            "otp_login" => $@"
                <p>¡Hola! 👋</p>
                <p>Has solicitado un código de acceso temporal (OTP) para iniciar sesión en tu cuenta de Floreria Bautista.</p>
                <div class=""code-container"">
                  <span class=""code"">{((dynamic)data).otpCode}</span>
                  <div class=""code-label"">Código de Acceso Temporal</div>
                </div>
                <div class=""warning-box"">
                  <p>⚠️ <strong>Nunca compartas este código con nadie.</strong> Nuestro equipo nunca te pedirá este código por teléfono o email.</p>
                </div>
                <div class=""info-box"">
                  <p>⏱️ Este código expira en <strong>10 minutos</strong> por tu seguridad.</p>
                </div>
                <p>Si no intentaste iniciar sesión, te recomendamos cambiar tu contraseña inmediatamente.</p>",

            "magic_link" => $@"
                <p>¡Hola! 👋</p>
                <p>Has solicitado un enlace de acceso rápido para iniciar sesión sin contraseña en Floreria Bautista.</p>
                <div class=""divider""></div>
                <div style=""text-align: center;"">
                  <a href=""{((dynamic)data).magicLink}"" class=""cta"">🔐 Iniciar Sesión Ahora</a>
                </div>
                <div class=""divider""></div>
                <div class=""warning-box"">
                  <p>🔒 <strong>Este enlace es de un solo uso.</strong> Una vez que lo uses, quedará invalidado automáticamente.</p>
                </div>
                <div class=""info-box"">
                  <p>⏱️ El enlace expira en <strong>15 minutos</strong>. Después de ese tiempo, necesitarás solicitar uno nuevo.</p>
                </div>
                <p>Si no solicitaste este enlace, puedes ignorar este correo. Tu cuenta permanece segura.</p>",

            "password_reset" => $@"
                <p>¡Hola! 👋</p>
                <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta en Floreria Bautista.</p>
                <div class=""divider""></div>
                <div style=""text-align: center;"">
                  <a href=""{((dynamic)data).resetLink}"" class=""cta"">🔑 Restablecer Contraseña</a>
                </div>
                <div class=""divider""></div>
                <div class=""warning-box"">
                  <p>⚠️ <strong>Si no solicitaste este cambio:</strong> Ignora este correo. Tu contraseña actual no se verá afectada y tu cuenta permanece segura.</p>
                </div>
                <div class=""info-box"">
                  <p>⏱️ Este enlace expira en <strong>1 hora</strong> por razones de seguridad.</p>
                </div>
                <p>Por tu seguridad, al cambiar tu contraseña cerraremos todas las sesiones activas en tus dispositivos.</p>",

            _ => "<p>Contenido no definido.</p>"
        };

        // Iconos por tipo
        string icon = type switch
        {
            "email_verification" => "✉️",
            "otp_login" => "🔐",
            "magic_link" => "✨",
            "password_reset" => "🔑",
            _ => "🔒"
        };

        var subject = ((dynamic)data).subject;

        return baseTemplate
            .Replace("{{subject}}", subject)
            .Replace("{{icon}}", icon)
            .Replace("{{content}}", specificContent);
    }

    public async Task SendVerificationEmailAsync(string email, string verificationCode)
    {
        var data = new
        {
            verificationCode,
            subject = "Verifica tu correo electrónico",
        };
        await SendEmailAsync(email, "email_verification", data);
    }

    public async Task SendOtpEmailAsync(string email, string otpCode)
    {
        var data = new
        {
            otpCode,
            subject = "Tu código de acceso temporal",
        };
        await SendEmailAsync(email, "otp_login", data);
    }

    public async Task SendMagicLinkEmailAsync(string email, string magicToken)
    {
<<<<<<< HEAD
        var magicLink = $"{_url}/magic?token={magicToken}";
=======
        var magicLink = $"https://is-2-front-end.vercel.app/#/auth/magic?token={magicToken}";
>>>>>>> 713e591e56f0f6836779f6cb09b0dc4677a4a43b

        var data = new
        {
            magicLink,
            subject = "Tu enlace de acceso rápido",
        };
        await SendEmailAsync(email, "magic_link", data);
    }

    public async Task SendPasswordResetEmailAsync(string email, string resetToken)
    {
<<<<<<< HEAD
        var resetLink = $"{_url}/reset?token={resetToken}";
=======
        var resetLink = $"https://is-2-front-end.vercel.app/#/auth/reset?token={resetToken}";
>>>>>>> 713e591e56f0f6836779f6cb09b0dc4677a4a43b

        var data = new
        {
            resetLink,
            subject = "Restablece tu contraseña",
        };
        await SendEmailAsync(email, "password_reset", data);
    }

    private async Task SendEmailAsync(string email, string type, object data)
    {
        var htmlContent = GetTemplateHtml(type, data);
        var subject = ((dynamic)data).subject;

        var payload = new
        {
            email,
            type,
            data = new { subject, html = htmlContent },
            timestamp = DateTime.UtcNow
        };

        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
        };

        var jsonContent = new StringContent(
            JsonSerializer.Serialize(payload, options),
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

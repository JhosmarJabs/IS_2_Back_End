# Backend - Sistema de Autenticación con JWT

Sistema completo de autenticación con ASP.NET Core, JWT, verificación de email via n8n y refresh tokens.

## 🚀 Características

- ✅ Registro de usuarios con hash SHA256
- ✅ Login con JWT (Access Token + Refresh Token)
- ✅ Verificación de email con código de 6 dígitos
- ✅ Integración con n8n para envío de emails
- ✅ Refresh tokens para renovar sesiones
- ✅ Sistema de roles (Admin, User)
- ✅ Protección de endpoints con [Authorize]
- ✅ Entity Framework Core con SQL Server

## 📋 Requisitos

- .NET 8.0 SDK
- SQL Server (o SQL Server Express)
- n8n instance (para envío de emails)

## 🔧 Instalación

### 1. Clonar y restaurar paquetes

```bash
dotnet restore
```

### 2. Instalar paquetes necesarios

```bash
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.EntityFrameworkCore.Tools
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package System.IdentityModel.Tokens.Jwt
```

### 3. Configurar la base de datos

Edita `appsettings.json` con tu cadena de conexión:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=AuthDb;User Id=sa;Password=TuPassword;TrustServerCertificate=True"
  }
}
```

### 4. Configurar JWT y n8n

Actualiza las configuraciones en `appsettings.json`:

```json
{
  "JwtSettings": {
    "Secret": "TuClaveSecretaSuperSeguraDeAlMenos32Caracteres123456",
    "Issuer": "TuApp",
    "Audience": "TusUsuarios"
  },
  "N8nSettings": {
    "WebhookUrl": "https://tu-instancia-n8n.com/webhook/verification-email"
  }
}
```

### 5. Crear y aplicar migraciones

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

### 6. Ejecutar la aplicación

```bash
dotnet run
```

La API estará disponible en `https://localhost:7000` (o el puerto configurado).

## 📡 Endpoints

### Autenticación

#### Registro
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "usuario@ejemplo.com",
  "password": "Password123",
  "firstName": "Juan",
  "lastName": "Pérez"
}
```

#### Verificar Email
```http
POST /api/auth/verify-email
Content-Type: application/json

{
  "email": "usuario@ejemplo.com",
  "token": "123456"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "usuario@ejemplo.com",
  "password": "Password123"
}
```

**Respuesta:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "qwerty123...",
  "expiresAt": "2024-01-01T12:00:00Z",
  "tokenType": "Bearer"
}
```

#### Refresh Token
```http
POST /api/auth/refresh-token
Content-Type: application/json

{
  "refreshToken": "qwerty123..."
}
```

#### Reenviar código de verificación
```http
POST /api/auth/resend-verification
Content-Type: application/json

{
  "email": "usuario@ejemplo.com"
}
```

### Usuario

#### Obtener usuario actual
```http
GET /api/user/me
Authorization: Bearer {accessToken}
```

#### Actualizar usuario
```http
PUT /api/user/me
Authorization: Bearer {accessToken}
Content-Type: application/json

{
  "firstName": "Juan Actualizado",
  "lastName": "Pérez García"
}
```

#### Eliminar cuenta
```http
DELETE /api/user/me
Authorization: Bearer {accessToken}
```

## 🔐 Configuración de n8n

Crea un workflow en n8n con un webhook trigger:

1. **Webhook Trigger** (POST)
2. **Function Node** para procesar datos:
```javascript
return {
  to: $json.email,
  subject: 'Verifica tu email',
  code: $json.verificationCode
};
```
3. **Email Node** para enviar el email con el código

## 🗄️ Estructura de Base de Datos

### Users
- Id (PK)
- Email (Unique)
- PasswordHash
- FirstName
- LastName
- IsEmailVerified
- CreatedAt
- UpdatedAt
- LastLoginAt

### Roles
- Id (PK)
- Name (Unique)
- Description

### UserRoles (Join Table)
- UserId (FK)
- RoleId (FK)

### VerificationTokens
- Id (PK)
- UserId (FK)
- Token (6 digits)
- ExpiresAt
- IsUsed

### RefreshTokens
- Id (PK)
- UserId (FK)
- Token
- ExpiresAt
- IsRevoked

## 🔒 Seguridad

- Contraseñas hasheadas con SHA256
- JWT con firma HMAC-SHA256
- Tokens de verificación expiran en 15 minutos
- Refresh tokens expiran en 7 días
- Validación de modelos con Data Annotations
- CORS configurado (ajustar para producción)

## 🛠️ Desarrollo

### Crear nueva migración
```bash
dotnet ef migrations add NombreDeLaMigracion
dotnet ef database update
```

### Eliminar última migración
```bash
dotnet ef migrations remove
```

### Ver migraciones aplicadas
```bash
dotnet ef migrations list
```

## 📦 Dependencias principales

- Microsoft.EntityFrameworkCore.SqlServer
- Microsoft.AspNetCore.Authentication.JwtBearer
- System.IdentityModel.Tokens.Jwt

## 🧪 Testing

Para probar los endpoints, puedes usar:
- Swagger UI: `/swagger`
- Postman
- Thunder Client (VS Code)
- curl

## 📝 Notas importantes

1. **Cambiar el secreto JWT** en producción a una clave más segura
2. **Configurar CORS** apropiadamente para tu dominio
3. **Usar HTTPS** en producción
4. **Implementar rate limiting** para prevenir ataques
5. **Agregar logging** con Serilog o NLog
6. **Considerar bcrypt** en lugar de SHA256 para passwords (más seguro)

## 🤝 Contribuir

1. Fork el proyecto
2. Crea una rama (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia MIT.

## 👨‍💻 Autor

Tu nombre - [@tuusuario](https://twitter.com/tuusuario)

## 🙏 Agradecimientos

- ASP.NET Core Team
- Entity Framework Core Team
- JWT.io
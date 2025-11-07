using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using IS_2_Back_End.DTOs;
using IS_2_Back_End.Repositories;

namespace IS_2_Back_End.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UserController : ControllerBase
{
    private readonly IUserRepository _userRepository;

    public UserController(IUserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    [HttpGet("me")]
    public async Task<IActionResult> GetCurrentUser()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
            {
                return Unauthorized(new { message = "Usuario no autenticado" });
            }

            var user = await _userRepository.GetByIdAsync(int.Parse(userId));
            if (user == null)
            {
                return NotFound(new { message = "Usuario no encontrado" });
            }

            var userResponse = new UserResponse
            {
                Id = user.Id,
                Email = user.Email,
                Phone = user.Phone,
                Nombre = user.Nombre,
                Apellido = user.Apellido,
                Sexo = user.Sexo,
                IsEmailVerified = user.IsVerified,
                CreatedAt = user.CreatedAt,
                Roles = user.UserRoles.Select(ur => ur.Role.Name).ToList()
            };

            return Ok(userResponse);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    [HttpPut("me")]
    public async Task<IActionResult> UpdateCurrentUser([FromBody] UpdateUserRequest request)
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
            {
                return Unauthorized(new { message = "Usuario no autenticado" });
            }

            var user = await _userRepository.GetByIdAsync(int.Parse(userId));
            if (user == null)
            {
                return NotFound(new { message = "Usuario no encontrado" });
            }

            // Actualizar campos
            if (!string.IsNullOrWhiteSpace(request.Phone))
                user.Phone = request.Phone;

            await _userRepository.UpdateAsync(user);

            var userResponse = new UserResponse
            {
                Id = user.Id,
                Email = user.Email,
                Phone = user.Phone,
                Nombre = user.Nombre,
                Apellido = user.Apellido,
                Sexo = user.Sexo,
                IsEmailVerified = user.IsVerified,
                CreatedAt = user.CreatedAt,
                Roles = user.UserRoles.Select(ur => ur.Role.Name).ToList()
            };

            return Ok(new { message = "Usuario actualizado exitosamente", user = userResponse });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    [HttpDelete("me")]
    public async Task<IActionResult> DeleteCurrentUser()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
            {
                return Unauthorized(new { message = "Usuario no autenticado" });
            }

            await _userRepository.DeleteAsync(int.Parse(userId));
            return Ok(new { message = "Usuario eliminado exitosamente" });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }

    [HttpGet("admin/users")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetAllUsers()
    {
        try
        {
            // Esta es una implementación básica
            // Deberías implementar paginación y filtros
            return Ok(new { message = "Endpoint para administradores - implementar según necesidades" });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "Error interno del servidor", error = ex.Message });
        }
    }
}

public class UpdateUserRequest
{
    public string? Phone { get; set; }
}
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using WebApiPeliculas2024I.Models;

namespace WebApiPeliculas2024I.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CuentasController : Controller
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly IConfiguration configuration;
        private readonly SignInManager<IdentityUser> signInManager;

        public CuentasController(IConfiguration configuration,
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager)
        {
            this.configuration = configuration;
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        private async Task<RespuestaAutenticacion> ConstruirToken(CredencialesUsuario
            credencialesUsuario)
        {
            //Creamos un claim con el email
            var claims = new List<Claim>()
            {
                new Claim("email", credencialesUsuario.Email),
            };
            //Encontramos el usuario
            var usuario = await userManager.FindByEmailAsync(credencialesUsuario.Email);
            //Obtenemos los claims de la base de datos del usuario
            var claimsRoles = await userManager.GetClaimsAsync(usuario!);

            claims.AddRange(claimsRoles);

            var llave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["LlaveJWT"]!));
            var creds = new SigningCredentials(llave, SecurityAlgorithms.HmacSha256);

            var expiracion = DateTime.Now.AddDays(1);

            var securityToken = new JwtSecurityToken(issuer: null, audience: null, claims: claims,
            expires: expiracion, signingCredentials: creds);

            return new RespuestaAutenticacion
            {
                Token = new JwtSecurityTokenHandler().WriteToken(securityToken),
                Expiracion = expiracion,
            };
        }

        [HttpGet("RenovarToken")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        private async Task<ActionResult<RespuestaAutenticacion>> Renovar()
        {
            var emailClaims = HttpContext.User.Claims.Where(x => x.Type == "email")
                    .FirstOrDefault();
            var credencialesUsuario = new CredencialesUsuario()
            {
                Email = emailClaims!.Value,
            };

            return await ConstruirToken(credencialesUsuario);
        }

        [HttpPost("registrar")]
        public async Task<ActionResult<RespuestaAutenticacion>> 
            Registrar(CredencialesUsuario credencialesUsuario)
        {
            var usuario = new IdentityUser
            {
                UserName = credencialesUsuario.Email,
                Email = credencialesUsuario.Email
            };

            var resultado = await userManager
                .CreateAsync(usuario, credencialesUsuario.Password);

            if (resultado.Succeeded)
                return await ConstruirToken(credencialesUsuario);

            return BadRequest(resultado.Errors);
        }

        [HttpPost("login")]
        public async Task<ActionResult<RespuestaAutenticacion>> 
            Login(CredencialesUsuario credencialesUsuario)
        {
            var resultado = await signInManager.PasswordSignInAsync(
                credencialesUsuario.Email, credencialesUsuario.Password,
                isPersistent: false, lockoutOnFailure: false);
            if (resultado.Succeeded)
                return await ConstruirToken(credencialesUsuario);

            var error = new MensajeError()
            {
                Error = "Login  incorrecto"
            };

            return BadRequest(error);
        }
    }
}

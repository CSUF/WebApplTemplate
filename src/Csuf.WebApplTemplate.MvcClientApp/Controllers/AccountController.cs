// (c) California State University, Fullerton.  All rights reserved.

namespace Csuf.WebApplTemplate.MvcClientApp
{
	using Microsoft.AspNetCore.Authentication;
	using Microsoft.AspNetCore.Authentication.Cookies;
	using Microsoft.AspNetCore.Authorization;
	using Microsoft.AspNetCore.Mvc;
	using Microsoft.Extensions.Configuration;
	using System.Linq;
	using System.Threading.Tasks;
	using static System.FormattableString;

	[AllowAnonymous]
	public sealed class AccountController : Controller
	{
		#region Private Fields

		private readonly IConfiguration _configuration;

		#endregion Private Fields

		#region Constructors

		public AccountController(IConfiguration configuration)
		{
			_configuration = configuration;
		}

		#endregion Constructors

		#region	Public Actions Functions

		[ValidateAntiForgeryToken]
		public async Task<ActionResult> SignOut()
		{
			AuthenticationProperties itemAuthenticationProperties = new AuthenticationProperties() { RedirectUri = Invariant($"{Request.Scheme}://{Request.Host}") };
			HttpContext.User.Identities.ToList().ForEach(id => HttpContext.SignOutAsync(id.AuthenticationType, itemAuthenticationProperties).ConfigureAwait(false));
			await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme, itemAuthenticationProperties).ConfigureAwait(false);
			await HttpContext.SignOutAsync("oidc", itemAuthenticationProperties).ConfigureAwait(false);
			return Redirect(Invariant($"{_configuration["CsufWebApplTemplate:OpenIdConnectAuthorityUrl"]}connect/endsession?id_token_hint={HttpContext.GetTokenAsync("id_token").Result}"));
		}

		#endregion
	}
}
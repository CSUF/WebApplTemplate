// (c) California State University, Fullerton. All rights reserved.

using Csuf.WebApplTemplate.MvcClientApp.Filters;
using Csuf.WebApplTemplate.MvcClientApp.Helpers;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using static System.FormattableString;
using static System.Globalization.CultureInfo;

namespace Csuf.WebApplTemplate.MvcClientApp
{
	public class Startup
	{
		public IConfiguration Configuration { get; }

		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}

		public void ConfigureServices(IServiceCollection services)
		{
			services.AddRouting(options => { options.LowercaseUrls = true; });
			services.AddLocalization(options => options.ResourcesPath = "Resources");

			services.Configure<CookiePolicyOptions>(options =>
			{
				options.HttpOnly = HttpOnlyPolicy.Always;
				options.Secure = CookieSecurePolicy.Always;
				options.CheckConsentNeeded = context => false;
				options.MinimumSameSitePolicy = SameSiteMode.None;
			});

			services.AddMvcCore(options =>
			{
				options.Filters.Add<SerilogLoggingPageFilter>();
			})
			.AddRazorPages()
			.AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix)
			.SetCompatibilityVersion(CompatibilityVersion.Version_3_0);

			services.AddMvc(options =>
			{
				options.Filters.Add<SerilogLoggingActionFilter>();
				AuthorizationPolicy policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
				options.Filters.Add(new AuthorizeFilter(policy));
				options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
			})
			.AddDataAnnotationsLocalization().AddRazorOptions(options => { });

			services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
			// Put your services.AddHttpClient<>() here...

			JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

			services.AddAuthentication(configureOptions: options =>
																									 {
																										 options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
																										 options.DefaultChallengeScheme = "oidc";
																										 options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
																									 })
							.AddCookie(authenticationScheme: CookieAuthenticationDefaults.AuthenticationScheme,
												 configureOptions: options =>
												 {
													 options.LogoutPath = new PathString("/account/signout");
													 options.Cookie = new CookieBuilder()
													 {
														 Name = Invariant($"CSUFWEBAPPLTEMPLATE{CookieAuthenticationDefaults.CookiePrefix}{CookieAuthenticationDefaults.AuthenticationScheme}"),
														 HttpOnly = true,
														 SecurePolicy = CookieSecurePolicy.Always,
														 SameSite = SameSiteMode.Lax
													 };
													 options.SlidingExpiration = false;
													 options.ExpireTimeSpan = TimeSpan.FromMinutes(Convert.ToInt32(Configuration["CsufWebApplTemplate:CookieAuthenticationExpireTimeSpanMinutes"], InvariantCulture));
												 })
							.AddOpenIdConnect(authenticationScheme: "oidc", configureOptions: options =>
							{
								options.Authority = Configuration["CsufWebApplTemplate:OpenIdConnectAuthorityUrl"];
								options.ClientId = Configuration["CsufWebApplTemplate:OpenIdConnectClientId"];
								options.ResponseType = "id_token token";
								options.UseTokenLifetime = false;
								options.RequireHttpsMetadata = true;
								options.TokenValidationParameters = new TokenValidationParameters { ValidateIssuer = false, NameClaimType = JwtClaimTypes.Name, RoleClaimType = JwtClaimTypes.Role };
								options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
								options.SaveTokens = true;
								options.GetClaimsFromUserInfoEndpoint = true;
								options.ProtocolValidator = new OpenIdConnectProtocolValidator()
								{
									RequireNonce = Convert.ToBoolean(Configuration["CsufWebApplTemplate:OpenIdConnectRequireNonce"], InvariantCulture),
									NonceLifetime = TimeSpan.FromMinutes(Convert.ToInt32(Configuration["CsufWebApplTemplate:OpenIdConnectNonceLifetimeMinutes"], InvariantCulture)),
									RequireStateValidation = false,
								};
								//options.Scope.Add("csufsampleapi");
								options.Events = new OpenIdConnectEvents()
								{
									OnAuthenticationFailed = (context) =>
									{
										// This will check if the authentication failed due to the Nonce expiration and force a refresh to ensure a new nonce is generated.
										if (context.Exception is OpenIdConnectProtocolInvalidNonceException && (context.Exception.Message.Contains("IDX10316") || context.Exception.Message.Contains("IDX10311")))
										{
											context.HandleResponse();
											context.Response.Redirect(context.HttpContext.Features.Get<IHttpRequestFeature>().RawTarget);  // Redirect to the originally requested URL
										}
										return Task.FromResult(0);
									},
									OnAuthorizationCodeReceived = (context) =>
									{
										Log.Debug("OnAuthorizationReceived");
										return Task.FromResult(0);
									},
									OnMessageReceived = (context) =>
									{
										Log.Debug("OnMessageReceived");
										return Task.FromResult(0);
									},
									OnRedirectToIdentityProvider = (context) =>
									{
										Log.Debug("OnRedirectToIdentityProvider");
										return Task.FromResult(0);
									},
									OnRedirectToIdentityProviderForSignOut = (context) =>
									{
										Log.Debug("OnRedirectToIdentityProviderForSignOut");
										var idTokenHint = context.HttpContext.GetTokenAsync("id_token").Result;
										if (idTokenHint != null)
										{
											Log.Debug($"idTokenHint = {idTokenHint}");
											context.ProtocolMessage.IdTokenHint = idTokenHint;
										}
										return Task.FromResult(0);
									},
									OnRemoteFailure = (context) =>
									{
										Log.Debug($"OnRemoteFailure {context.Failure.Message}");
										if (context.Failure.Message.Contains("Correlation failed", StringComparison.OrdinalIgnoreCase))
										{
											context.HandleResponse();
											string originalRequestedUrl = context.HttpContext.Features.Get<IHttpRequestFeature>().RawTarget;
											context.Response.Redirect(originalRequestedUrl.Replace(@"/signin-oidc", @"/home", StringComparison.OrdinalIgnoreCase));
										}
										return Task.FromResult(0);
									},
									OnRemoteSignOut = (context) =>
									{
										Log.Debug("OnRemoteSignOut");
										return Task.FromResult(0);
									},
									OnSignedOutCallbackRedirect = (context) =>
									{
										Log.Debug("OnSignedOutCallbackRedirect");
										return Task.FromResult(0);
									},
									OnTicketReceived = (context) =>
									{
										Log.Debug("OnTicketReceived");
										return Task.FromResult(0);
									},
									OnTokenResponseReceived = (context) =>
									{
										Log.Debug("OnTokenResponseReceived");
										return Task.FromResult(0);
									},
									OnTokenValidated = (context) =>
									{
										Log.Debug("OnTokenValidated");
										var nid = new ClaimsIdentity(context.Principal.Identity.AuthenticationType, JwtClaimTypes.Name, JwtClaimTypes.Role);
										context.Principal.Claims.ToList().ForEach(x => nid.AddClaim(x));
										// Do your Claim Transformation here..
										context.Principal = new ClaimsPrincipal(identity: nid);
										return Task.FromResult(0);
									},
									OnUserInformationReceived = (context) =>
									{
										Log.Debug("OnUserInformationReceived");
										return Task.FromResult(0);
									},
								};
							});
			services.AddHealthChecks();
		}

		public void Configure(IApplicationBuilder app)
		{
			app.Use(async (context, next) =>
			{
				if (context.Request.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)) context.Request.Scheme = "https";
				await next.Invoke();
			});
			Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;

			app.UseStatusCodePagesWithReExecute(pathFormat: "/home/error", queryFormat: "?statusCode={0}");
			app.UseExceptionHandler("/home/error");

			app.UseHsts(hsts => hsts.MaxAge(365).IncludeSubdomains());
			app.UseHttpsRedirection();

			app.UseXContentTypeOptions();
			app.UseReferrerPolicy(opts => opts.NoReferrer());
			app.UseXXssProtection(options => options.EnabledWithBlockMode());
			app.UseXfo(options => options.Deny());
			app.UseNoCacheHttpHeaders();
			app.UseXRobotsTag(options => options.NoIndex().NoFollow());

			app.UseStaticFiles();
			app.UseSerilogRequestLogging(opts =>
			{
				opts.EnrichDiagnosticContext = LogHelper.EnrichFromRequest;
				opts.GetLevel = LogHelper.ExcludeHealthChecks;
			});
			app.UseRouting();
			app.UseCookiePolicy(new CookiePolicyOptions() { MinimumSameSitePolicy = SameSiteMode.None });

			app.UseAuthentication();
			app.UseAuthorization();

			app.UseEndpoints(endpoints =>
			{
				endpoints.MapHealthChecks("/healthz");
				endpoints.MapControllers();
				endpoints.MapDefaultControllerRoute();
				endpoints.MapControllerRoute(name: "DefaultRoute", pattern: "{controller=Home}/{action=Index}/{id?}");
			});
		}
	}
}
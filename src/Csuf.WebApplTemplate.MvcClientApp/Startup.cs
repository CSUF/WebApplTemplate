// (c) California State University, Fullerton. All rights reserved.

namespace Csuf.WebApplTemplate
{
	using IdentityModel;
	using Microsoft.AspNetCore.Authentication.Cookies;
	using Microsoft.AspNetCore.Authentication.OpenIdConnect;
	using Microsoft.AspNetCore.Authorization;
	using Microsoft.AspNetCore.Builder;
	using Microsoft.AspNetCore.Hosting;
	using Microsoft.AspNetCore.Http;
	using Microsoft.AspNetCore.Http.Features;
	using Microsoft.AspNetCore.Mvc;
	using Microsoft.AspNetCore.Mvc.Authorization;
	using Microsoft.AspNetCore.Mvc.Razor;
	using Microsoft.AspNetCore.Routing;
	using Microsoft.Extensions.Configuration;
	using Microsoft.Extensions.DependencyInjection;
	using Microsoft.IdentityModel.Protocols.OpenIdConnect;
	using Microsoft.IdentityModel.Tokens;
	using System;
	using System.IdentityModel.Tokens.Jwt;
	using System.Threading.Tasks;
	using static System.FormattableString;
	using static System.Globalization.CultureInfo;


	public class Startup
	{
		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}

		public IConfiguration Configuration { get; }

		public void ConfigureServices(IServiceCollection services)
		{

			services.AddRouting(options => { options.LowercaseUrls = true; });
			services.AddLocalization(options => options.ResourcesPath = "Resources");

			services.Configure<CookiePolicyOptions>(options =>
			{
				// This lambda determines whether user consent for non-essential cookies is needed for a given request.
				options.CheckConsentNeeded = context => false;
				options.MinimumSameSitePolicy = SameSiteMode.None;
			});


			services.AddMvc(options =>
			{
				AuthorizationPolicy policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
				options.Filters.Add(new AuthorizeFilter(policy));
				options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
			})
				.AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix)
				.AddDataAnnotationsLocalization().AddRazorOptions(options => { })
				.SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

			services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

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
														 SameSite = SameSiteMode.Lax,
														 Expiration = TimeSpan.FromMinutes(Convert.ToInt32(Configuration["CsufWebApplTemplate:CookieAuthenticationExpireTimeSpanMinutes"], InvariantCulture)),
													 };
													 options.SlidingExpiration = false;
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
								};
							});

		}

		public void Configure(IApplicationBuilder app, IHostingEnvironment env)
		{
			app.Use(async (context, next) =>
			{
				if (context.Request.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)) context.Request.Scheme = "https";
				await next.Invoke();
			});

			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}
			else
			{
				app.UseExceptionHandler("/Home/Error");
				app.UseHsts();
			}

			app.UseHttpsRedirection();
			app.UseAuthentication();

			app.UseStaticFiles();
			app.UseCookiePolicy();

			app.UseHsts(hsts => hsts.MaxAge(365).IncludeSubdomains());
			app.UseXContentTypeOptions();
			app.UseReferrerPolicy(opts => opts.NoReferrer());
			app.UseXXssProtection(options => options.EnabledWithBlockMode());
			app.UseXfo(options => options.Deny());

			app.UseStaticFiles();
			app.UseNoCacheHttpHeaders();
			app.UseXRobotsTag(options => options.NoIndex().NoFollow());

			app.UseCookiePolicy(new CookiePolicyOptions()
			{
				MinimumSameSitePolicy = SameSiteMode.None
			});


			app.UseMvc(routes =>
			{
				routes.MapRoute(
									name: "default",
									template: "{controller=Home}/{action=Index}/{id?}");
			});

			app.UseMvc(routes =>
			{
				routes.MapRoute(name: "DefaultRoute", template: "{controller=Home}/{action=Index}/{id?}");
			});

		}
	}
}

// (c) California State University, Fullerton.  All rights reserved.

using Microsoft.AspNetCore.Http;
using Serilog;
using Serilog.Context;
using Serilog.Events;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Csuf.WebApplTemplate.MvcClientApp.Helpers
{
	internal sealed class CustomEnricherHttpContextInfo
	{
		public string RequestPath { get; set; }
		public string Host { get; set; }
		public string RequestMethod { get; set; }
		public string ClientIP { get; set; }
		public string EndpointName { get; set; }
		public string CurrentUserName { get; set; }
		public Dictionary<string, string> UserClaims { get; set; } //public List<KeyValuePair<string, string>> UserClaims { get; set; }
		public string QueryString { get; set; }
		public List<KeyValuePair<string, string>> Query { get; set; }
		public string Referer { get; set; }
		public string UserAgent { get; set; }
		public string Scheme { get; set; }
		public string Protocol { get; set; }
		public string XOriginalFor { get; set; }
		public string XOriginalProto { get; set; }
		public string ResponseContentType { get; set; }
		public string CorrelationId { get; set; }
		public string MachineName { get; set; }
	}

	public static class LogHelper
	{
		public static void EnrichFromRequest(IDiagnosticContext diagnosticContext, HttpContext context)
		{
			if (context != null)
			{
				CustomEnricherHttpContextInfo theInfo = new CustomEnricherHttpContextInfo()
				{
					RequestPath = context.Request.Path.ToString(),
					Host = context.Request.Host.ToString(),
					RequestMethod = context.Request.Method,
					ClientIP = context.Connection.RemoteIpAddress.MapToIPv4().ToString(),
					Scheme = context.Request.Scheme,
					Protocol = context.Request.Protocol,
					QueryString = (context.Request.QueryString.HasValue) ? context.Request.QueryString.Value : null,
					ResponseContentType = context.Response.ContentType
				};
				diagnosticContext.Set("FullRequest", $"{theInfo.RequestMethod} {theInfo.Scheme}://{theInfo.Host.Trim('/')}{theInfo.RequestPath}{theInfo.QueryString} {theInfo.Protocol}");
				if (!string.IsNullOrWhiteSpace(theInfo.ClientIP)) diagnosticContext.Set(nameof(theInfo.ClientIP), theInfo.ClientIP);
				if (!string.IsNullOrWhiteSpace(theInfo.ClientIP)) diagnosticContext.Set(nameof(theInfo.ResponseContentType), theInfo.ResponseContentType);

				var currentUser = context.User;
				if (currentUser != null && currentUser.Identity != null && currentUser.Identity.IsAuthenticated)
				{
					theInfo.CurrentUserName = currentUser.Identity.Name;
					diagnosticContext.Set(nameof(theInfo.CurrentUserName), theInfo.CurrentUserName);
					int i = 0;
					theInfo.UserClaims = currentUser.Claims.ToDictionary(x => $"{x.Type} ({i++})", y => y.Value);
					diagnosticContext.Set(nameof(theInfo.UserClaims), theInfo.UserClaims);
				}

				var endpoint = context.GetEndpoint();
				if (endpoint is object)
				{
					theInfo.EndpointName = endpoint.DisplayName;
					diagnosticContext.Set(nameof(theInfo.EndpointName), theInfo.EndpointName);
				};
				if (context.Request.Headers.ContainsKey("User-Agent"))
				{
					theInfo.UserAgent = context.Request.Headers["User-Agent"];
					diagnosticContext.Set(nameof(theInfo.UserAgent), theInfo.UserAgent);
				}
				if (context.Request.Headers.ContainsKey("Referer"))
				{
					theInfo.Referer = context.Request.Headers["Referer"];
					diagnosticContext.Set(nameof(theInfo.Referer), theInfo.Referer);
				}
				if (context.Request.Headers.ContainsKey("X-Forwarded-For"))
				{
					theInfo.ClientIP = context.Request.Headers["X-Forwarded-For"];
					diagnosticContext.Set(nameof(theInfo.ClientIP), theInfo.ClientIP);
				};
				if (context.Request.Headers.ContainsKey("X-Original-For"))
				{
					theInfo.XOriginalFor = context.Request.Headers["X-Original-For"];
					diagnosticContext.Set(nameof(theInfo.XOriginalFor), theInfo.XOriginalFor);
				}
				if (context.Request.Headers.ContainsKey("X-Original-Proto"))
				{
					theInfo.XOriginalProto = context.Request.Headers["X-Original-Proto"];
					diagnosticContext.Set(nameof(theInfo.XOriginalProto), theInfo.XOriginalProto);
				}
			}
		}

		private static CustomEnricherHttpContextInfo CustomEnricherLogic(IHttpContextAccessor ctx)
		{
			HttpContext context = ctx.HttpContext;
			if (context == null) return null;

			CustomEnricherHttpContextInfo theInfo = new CustomEnricherHttpContextInfo()
			{
				RequestPath = context.Request.Path.ToString(),
				Host = context.Request.Host.ToString(),
				RequestMethod = context.Request.Method,
				ClientIP = context.Connection.RemoteIpAddress.MapToIPv4().ToString(),
				QueryString = (context.Request.QueryString.HasValue) ? context.Request.QueryString.Value : null,
				Scheme = context.Request.Scheme,
				Protocol = context.Request.Protocol,
				ResponseContentType = context.Response.ContentType
			};
			LogContext.PushProperty("FullRequest", $"{theInfo.RequestMethod} {theInfo.Scheme}://{theInfo.Host.Trim('/')}{theInfo.RequestPath}{theInfo.QueryString} {theInfo.Protocol}");
			if (!string.IsNullOrWhiteSpace(theInfo.ClientIP)) LogContext.PushProperty(nameof(theInfo.ClientIP), theInfo.ClientIP);
			if (!string.IsNullOrWhiteSpace(theInfo.ResponseContentType)) LogContext.PushProperty(nameof(theInfo.ResponseContentType), theInfo.ResponseContentType);

			var currentUser = context.User;
			if (currentUser != null && currentUser.Identity != null && currentUser.Identity.IsAuthenticated)
			{
				theInfo.CurrentUserName = currentUser.Identity.Name;
				LogContext.PushProperty(nameof(theInfo.CurrentUserName), theInfo.CurrentUserName);
				int i = 0;
				theInfo.UserClaims = currentUser.Claims.ToDictionary(x => $"{x.Type} ({i++})", y => y.Value);
				//myInfo.UserClaims = currentUser.Claims.Select(a => new KeyValuePair<string, string>(a.Type, a.Value)).ToList();
				LogContext.PushProperty(nameof(theInfo.UserClaims), theInfo.UserClaims);
			}

			var endpoint = context.GetEndpoint();
			if (endpoint is object)
			{
				theInfo.EndpointName = endpoint.DisplayName;
				LogContext.PushProperty(nameof(theInfo.EndpointName), theInfo.EndpointName);
			}

			if (context.Request.Query != null && context.Request.Query.Count > 0)
			{
				theInfo.Query = context.Request.Query.Select(q => new KeyValuePair<string, string>(q.Key, q.Value)).ToList();
				LogContext.PushProperty(nameof(theInfo.Query), theInfo.Query);
			}
			if (context.Request.Headers.ContainsKey("User-Agent"))
			{
				theInfo.UserAgent = context.Request.Headers["User-Agent"];
				LogContext.PushProperty(nameof(theInfo.UserAgent), theInfo.UserAgent);
			}
			if (context.Request.Headers.ContainsKey("Referer"))
			{
				theInfo.Referer = context.Request.Headers["Referer"];
				LogContext.PushProperty(nameof(theInfo.Referer), theInfo.Referer);
			}
			if (context.Request.Headers.ContainsKey("X-Forwarded-For"))
			{
				theInfo.ClientIP = context.Request.Headers["X-Forwarded-For"];
				LogContext.PushProperty(nameof(theInfo.ClientIP), theInfo.ClientIP);
			}
			if (context.Request.Headers.ContainsKey("X-Original-For"))
			{
				theInfo.XOriginalFor = context.Request.Headers["X-Original-For"];
				LogContext.PushProperty(nameof(theInfo.XOriginalFor), theInfo.XOriginalFor);
			}
			if (context.Request.Headers.ContainsKey("X-Original-Proto"))
			{
				theInfo.XOriginalProto = context.Request.Headers["X-Original-Proto"];
				LogContext.PushProperty(nameof(theInfo.XOriginalProto), theInfo.XOriginalFor);
			}
			return theInfo;
		}

		private static bool IsHealthCheckEndpoint(HttpContext ctx)
		{
			var endpoint = ctx.GetEndpoint();
			if (endpoint is object) // same as !(endpoint is null)
			{
				return string.Equals(endpoint.DisplayName, "Health checks", StringComparison.Ordinal);
			}
			// No endpoint, so not a health check endpoint
			return false;
		}

		public static LogEventLevel ExcludeHealthChecks(HttpContext ctx, double _, Exception ex) =>
				ex != null
						? LogEventLevel.Error
						: ctx.Response.StatusCode > 499
								? LogEventLevel.Error
								: IsHealthCheckEndpoint(ctx) // Not an error, check if it was a health check
										? LogEventLevel.Verbose // Was a health check, use Verbose
										: LogEventLevel.Information;

		public static LogEventLevel CustomGetLevel(HttpContext ctx, double _, Exception ex) =>
					 ex != null
							 ? LogEventLevel.Error
							 : ctx.Response.StatusCode > 499
									 ? LogEventLevel.Error
									 : LogEventLevel.Debug; //Debug instead of Information

		/// <summary>
		/// Create a <see cref="Serilog.AspNetCore.RequestLoggingOptions.GetLevel"> method that
		/// uses the default logging level, except for the specified endpoint names, which are
		/// logged using the provided <paramref name="traceLevel" />.
		/// </summary>
		/// <param name="traceLevel">The level to use for logging "trace" endpoints</param>
		/// <param name="traceEndointNames">The display name of endpoints to be considered "trace" endpoints</param>
		/// <returns></returns>
		public static Func<HttpContext, double, Exception, LogEventLevel> GetLevel(LogEventLevel traceLevel, params string[] traceEndointNames)
		{
			if (traceEndointNames is null || traceEndointNames.Length == 0)
			{
				throw new ArgumentNullException(nameof(traceEndointNames));
			}

			return (ctx, _, ex) =>
					IsError(ctx, ex)
					? LogEventLevel.Error
					: IsTraceEndpoint(ctx, traceEndointNames)
							? traceLevel
							: LogEventLevel.Information;
		}

		private static bool IsError(HttpContext ctx, Exception ex)
				=> ex != null || ctx.Response.StatusCode > 499;

		private static bool IsTraceEndpoint(HttpContext ctx, string[] traceEndoints)
		{
			var endpoint = ctx.GetEndpoint();
			if (endpoint is object)
			{
				for (var i = 0; i < traceEndoints.Length; i++)
				{
					if (string.Equals(traceEndoints[i], endpoint.DisplayName, StringComparison.OrdinalIgnoreCase))
					{
						return true;
					}
				}
			}
			return false;
		}
	}
}
// (c) California State University, Fullerton. All rights reserved.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Enrichers.AspnetcoreHttpcontext;
using Serilog.Exceptions;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace Csuf.WebApplTemplate.MvcClientApp
{
	public class Program
	{
		public static IConfiguration Configuration { get; set; }

		private static string _environmentName;

		public static int Main(string[] args)
		{
			Serilog.Debugging.SelfLog.Enable(msg =>
			{
				string devEnvironmentVariable = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
				var isDevelopment = string.IsNullOrWhiteSpace(devEnvironmentVariable) || devEnvironmentVariable.Equals("Development", StringComparison.OrdinalIgnoreCase);
				if (isDevelopment)
				{
					Console.WriteLine(msg);
					Debug.Print(msg);
					Debugger.Break();
				}
			});
			try
			{
				CreateHostBuilder(args).Build().Run();
				return 0;
			}
			catch (Exception ex)
			{
				Log.Fatal(ex, "Host terminated unexpectedly");
				Console.WriteLine("Host terminated unexpectedly");
				Console.Write(ex.ToString());
				return 1;
			}
			finally
			{
				Log.CloseAndFlush();
			}
		}

		public static IHostBuilder CreateHostBuilder(string[] args) => Host.CreateDefaultBuilder(args)
		.ConfigureWebHostDefaults(webBuilder =>
		{
			webBuilder.UseKestrel(c => c.AddServerHeader = false);
			webBuilder.UseStartup<Startup>();
		})
		.ConfigureHostConfiguration(builder =>
		{
			string devEnvironmentVariable = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
			var isDevelopment = string.IsNullOrWhiteSpace(devEnvironmentVariable) || devEnvironmentVariable.ToLower() == "development";
			if (isDevelopment) builder.AddUserSecrets<Program>();
			builder.SetBasePath(Directory.GetCurrentDirectory())  // AppContext.BaseDirectory
				.AddJsonFile(path: "appsettings.json", optional: false, reloadOnChange: true)
				.AddEnvironmentVariables()
				.Build();
			Configuration = builder.Build();
			if (builder == null)
			{
				throw new Exception("Missing or invalid appsettings.json file. Please see README.md for configuration instructions.");
			}
		})
		.ConfigureLogging((hostingContext, config) =>
		{
			config.ClearProviders();
			_environmentName = hostingContext.HostingEnvironment.EnvironmentName;
		})
		.UseSerilog((hostingContext, loggerConfiguration) =>
		{
			var name = Assembly.GetExecutingAssembly().GetName();
			loggerConfiguration
				.Enrich.FromLogContext()
				.Enrich.WithExceptionDetails()
				.Enrich.WithProperty("Assembly", $"{name.Name}")
				.Enrich.WithProperty("Version", $"{name.Version}")
				.Enrich.WithMachineName()
				.Enrich.WithThreadId()
				.ReadFrom.Configuration(Configuration);
		});
	}
}
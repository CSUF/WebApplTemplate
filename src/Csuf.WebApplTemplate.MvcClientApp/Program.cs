// (c) California State University, Fullerton. All rights reserved.

namespace Csuf.WebApplTemplate
{

	using Microsoft.AspNetCore;
	using Microsoft.AspNetCore.Hosting;
	using Microsoft.Extensions.Configuration;
	using Microsoft.Extensions.Logging;
	using Serilog;
	using Serilog.Exceptions;
	using System;
	using System.IO;

	public class Program
	{

		public static IConfiguration Configuration { get; } = new ConfigurationBuilder()
			.SetBasePath(Directory.GetCurrentDirectory())
			.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
			.AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
			.AddEnvironmentVariables()
			.Build();

		private static string _environmentName;

		public static void Main(string[] args)
		{
			Log.Logger = new LoggerConfiguration()
				.Enrich.FromLogContext()
				.Enrich.WithMachineName()
				.Enrich.WithThreadId()
				.Enrich.WithExceptionDetails()
				.ReadFrom.Configuration(Configuration)
				.WriteTo.Console()
				.CreateLogger();
			try
			{
				Log.Information("Starting web host");
				CreateWebHostBuilder(args).Build().Run();
			}
			catch (Exception ex)
			{
				Log.Fatal(ex, "Host terminated unexpectedly");
			}
			finally
			{
				Log.CloseAndFlush();
			}
		}

		public static IWebHostBuilder CreateWebHostBuilder(string[] args)
		{
			return WebHost.CreateDefaultBuilder(args)
				 .ConfigureLogging((hostingContext, config) =>
				 {
					 config.ClearProviders();
					 _environmentName = hostingContext.HostingEnvironment.EnvironmentName;
				 })
				 .UseKestrel(c => c.AddServerHeader = false)
				 .UseStartup<Startup>()
				 .UseConfiguration(Configuration)
				 .UseSerilog();
			;
		}

	}
}

// (c) California State University, Fullerton. All rights reserved.

using Csuf.WebApplTemplate.MvcClientApp.Models;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Serilog;
using System.Diagnostics;
using System.Text.Json;

namespace Csuf.WebApplTemplate.MvcClientApp.Controllers
{
	public class HomeController : Controller
	{
		public IActionResult Index()
		{
			//throw new InvalidOperationException("This is a test exception");
			return View();
		}

		[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
		public IActionResult Error(int? statusCode = null)
		{
			ErrorViewModel modelResult = new ErrorViewModel() { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier };
			if (HttpContext.Features.Get<IStatusCodeReExecuteFeature>() is StatusCodeReExecuteFeature reExecuteFeature)
			{
				modelResult.OriginalPath = reExecuteFeature?.OriginalPath;
				modelResult.OriginalPathBase = reExecuteFeature?.OriginalPathBase;
				modelResult.OriginalQueryString = reExecuteFeature?.OriginalQueryString;
				Log.Warning("Status Code: {statusCode} from request {OriginalPathBase}{OriginalPath}{OriginalQueryString} Request ID: {RequestId}",
					statusCode, modelResult.OriginalPathBase, modelResult.OriginalPath, modelResult.OriginalQueryString, modelResult.RequestId);
			}
			if (HttpContext.Features.Get<IExceptionHandlerPathFeature>() is ExceptionHandlerFeature exceptionFeature)
			{
				if (exceptionFeature != null)
				{
					modelResult.RouteOfException = exceptionFeature.Path;
					if (exceptionFeature.Error != null)
					{
						modelResult.ErrorTargetSiteName = exceptionFeature.Error.TargetSite.Name;
						modelResult.ErrorMessage = $"{exceptionFeature.Error.InnerException?.Message} | {exceptionFeature.Error?.Message}";
						modelResult.ErrorSource = exceptionFeature.Error.Source;
						modelResult.ErrorStackTrace = exceptionFeature.Error.StackTrace;
						modelResult.ErrorData = JsonConvert.SerializeObject(exceptionFeature.Error.Data);
					}
				}
			}
			return View(viewName: "Error", model: modelResult);
		}
	}
}
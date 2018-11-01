// (c) California State University, Fullerton. All rights reserved.


namespace Csuf.WebApplTemplate.Controllers
{
	using Csuf.WebApplTemplate.Models;
	using Microsoft.AspNetCore.Mvc;
	using System.Diagnostics;

	public class HomeController : Controller
	{
		public IActionResult Index()
		{
			return View();
		}

		public IActionResult About()
		{
			ViewData["Message"] = "Your application description page.";
			return View();
		}

		public IActionResult Contact()
		{
			ViewData["Message"] = "Your contact page.";
			return View();
		}

		public IActionResult Privacy()
		{
			return View();
		}

		[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
		public IActionResult Error()
		{
			return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
		}
	}
}

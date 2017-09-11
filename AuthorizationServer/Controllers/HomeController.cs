using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace AuthorizationServer.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Message = "Site - Teste Developer";

            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Home";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "www.testedeveloperfcamara.com";

            return View();
        }
    }
}

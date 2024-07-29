using DE3.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Entity;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace DE3.Controllers
{
    public class HomeController : Controller
    {
        DE3Entities db = new DE3Entities();
        public ActionResult Index()
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            List<CVCha> list = db.CVChas.Where(x => x.IsDelete == false).ToList();
            return View(list);
        }

        public ActionResult Login()
        {
            return View();
        }
        public ActionResult LogOut()
        {
            Session["Login"] = null;
            return View("Login");
        }

        public bool checkToken()
        {
            var access_token = Session["access_token"];
            if (access_token == null)
            {
                //return RedirectToAction("Login");
                return false;
            }
            else
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(Convert.ToString(ConfigurationManager.AppSettings["config:JwtKey"]));
                tokenHandler.ValidateToken(access_token.ToString(), new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero

                }, out SecurityToken validatedToken);

                // Corrected access to the validatedToken
                var jwtToken = (JwtSecurityToken)validatedToken;
                if (jwtToken.ValidTo < DateTime.UtcNow)
                {
                    return false;
                    //return RedirectToAction(Action);
                }


            }
            return true;
            //return RedirectToAction("Login");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(Login user)
        {
            var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["config:JwtKey"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            string hashedPassword = HashPassword(user.Password, "12345!#aB");
            User u = db.Users.FirstOrDefault(x => x.UserName == user.UserName && x.Pass == hashedPassword && x.Role == 1); //pass: 12345


            if (u != null)
            {
                var claims = new[]
        { new Claim("ID", u.ID.ToString()),
                    new Claim("UserName", u.UserName),
                    new Claim("Role", u.Role.ToString())
                    // Add more claims if needed
                };

                var accessToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddHours(1), // Token expires in 1 hour
                    signingCredentials: credentials
                );

                var refreshToken = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddDays(7), // Token expires in 7day
                    signingCredentials: credentials
                );
                var access_token = new JwtSecurityTokenHandler().WriteToken(accessToken);
                var refresh_token = new JwtSecurityTokenHandler().WriteToken(refreshToken);
                Models.Token to = new Models.Token()
                {
                    Users_ID = u.ID,
                    access_token = access_token,
                    refresh_token = refresh_token,
                };
                db.Tokens.Add(to);
                db.SaveChanges();

                Session["access_token"] = access_token;
                //Session["refresh_token"] = refresh_token;
                Session["Login"] = true;
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError("", "Login data is incorrect!");
            }
            return View();
        }
        public ActionResult Error(string MaError)
        {
            ViewBag.Error = MaError;
            return View();
        }

        public ActionResult Success(string Success)
        {
            ViewBag.Success = Success;
            return View();
        }
        public ActionResult Create()
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            return View();
        }
        [HttpPost]
        public ActionResult Create(FormCollection collection, CVCha cv)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            try
            {
                if (db.CVChas.SingleOrDefault(x => x.TenCV.Equals(cv.TenCV)) == null)
                {
                    cv.IsDelete = false;
                    db.CVChas.Add(cv);

                    db.SaveChanges();
                    return RedirectToAction("Success", "Home", new { Success = "Thêm đầu công việc thành công" });
                }
                else
                {
                    return RedirectToAction("Error", "Home", new { @MaError = "Thêm đầu công việc thất bại" });
                }

               

        }
            catch
            {
               return RedirectToAction("Error", "Home", new { @MaError = "Thêm đầu công việc thất bại" });
            }
        }


        public ActionResult Details(int? id)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            ViewBag.id = id;
            List<CVCon> list = db.CVCons.Where(n => n.IsDelete == false && n.CvChaID == id && n.CVCha.IsDelete == false).ToList();
           
            return View(list);
        }
        public ActionResult Delete(int id)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return Json(new { mess = "fail" }, JsonRequestBehavior.AllowGet);
            }
            CVCha nen = db.CVChas.Find(id);
            if (nen == null)
            {
                return Json(new { mess = "fail" }, JsonRequestBehavior.AllowGet);
            }
            nen.IsDelete = true;
            db.SaveChanges();
            return Json(new { mess = "success" }, JsonRequestBehavior.AllowGet);
        }
        public ActionResult CreateCVCon(int id)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            ViewBag.id = id;
            return View();
        }
        [HttpPost]
        public ActionResult CreateCVCon(FormCollection collection, CVCon cv)
        {

            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            try
            {
                if (db.CVCons.SingleOrDefault(x => x.TenCV.Equals(cv.TenCV)) == null)
                {
                    if (cv.NguoiGiao == "ko" || cv.NguoiTH == "ko")
                    {
                        return RedirectToAction("Error", "Home", new { @MaError = "Thêm công việc thất bại" });
                    }
                    cv.IsDelete = false;
                    db.CVCons.Add(cv);

                    db.SaveChanges();
                    return RedirectToAction("Success", "Home", new { Success = "Thêm công việc thành công" });
                }
                else
                {
                    return RedirectToAction("Error", "Home", new { @MaError = "Thêm công việc thất bại" });
                }



            }
            catch
            {
                return RedirectToAction("Error", "Home", new { @MaError = "Thêm công việc thất bại" });
            }
        }
        public ActionResult Edit(int id)
        {

            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }

            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            CVCha nen = db.CVChas.Find(id);
            if (nen == null)
            {
                return HttpNotFound();
            }
            return View(nen);
        }
        [HttpPost]
        public ActionResult Edit(CVCha nen, FormCollection collection)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (nen.ID != null)
            {
                CVCha cv = db.CVChas.SingleOrDefault(n => n.ID == nen.ID);
                cv.IsDelete = false;
                cv.TenCV = nen.TenCV;
                cv.MoTa = nen.MoTa;
                db.Entry(cv).State = EntityState.Modified;
                db.SaveChanges();
            }

            return RedirectToAction("Success", "Home", new { Success = "Sửa công việc thành công" });


        }
        public ActionResult EditCVCon(int id)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            CVCon nen = db.CVCons.Find(id);
            if (nen == null)
            {
                return HttpNotFound();
            }
            return View(nen);
        }
        [HttpPost]
        public ActionResult EditCVCon(CVCon nen, FormCollection collection)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            if (nen.ID != null)
            {
                CVCon cv = db.CVCons.SingleOrDefault(n => n.ID == nen.ID);
                cv.IsDelete = false;
                cv.TenCV = nen.TenCV;
                cv.MoTa = nen.MoTa;
                cv.ThgianBD = nen.ThgianBD;
                cv.ThgianKT = nen.ThgianKT;
                cv.NguoiTH = nen.NguoiTH;
                cv.NguoiGiao = nen.NguoiGiao;
                db.Entry(cv).State = EntityState.Modified;
                db.SaveChanges();
            }

            return RedirectToAction("Success", "Home", new { Success = "Sửa công việc thành công" });


        }
        public ActionResult CVCaNhan(string name)
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            List<CVCon> list = db.CVCons.Where(n => n.NguoiTH.Equals(name)).ToList();
            
            return View(list);
        }
        public ActionResult CVCuaToi(string name = "Huyền")
        {
            //check token còn thời gian k
            bool check = checkToken();
            if (!check)
            {
                return RedirectToAction("Login");
            }
            DateTime date = DateTime.Now;
            List<CVCon> list = db.CVCons.Where(n => n.NguoiTH.Equals(name) && n.ThgianBD.Value.Day == date.Day && n.ThgianBD.Value.Month == date.Month && n.ThgianBD.Value.Year == date.Year ).ToList();

            return View(list);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(FormCollection collection, User u)
        {
            string pass = u.Pass;
            string rePass = collection["RePassword"];
            if (!pass.Equals(rePass))
            {
                return RedirectToAction("Error", "Home", new { @MaError = "Mật khẩu không trùng khớp!" });

            }
            if (db.Users.SingleOrDefault(x => x.UserName.Equals(u.UserName)) != null)
            {

                return RedirectToAction("Error", "Home", new { @MaError = "Tên Username đã tồn tại!" });


            }
            
            string hashedPassword = HashPassword(pass, "12345!#aB");
            User user = new User()
            {
                UserName = u.UserName,
                Pass = hashedPassword,
                Role = 1,
               
            };
            db.Users.Add(user);
            db.SaveChanges();
            return RedirectToAction("Success", "Home", new { Success = "Tạo tài khoản thành công" });
        }
        public ActionResult Register()
        {
            return View();
        }
        public static string HashPassword(string password, string salt)
        {
            using (var sha256 = SHA256.Create())
            {
                var saltedPassword = password + salt;
                var passwordBytes = Encoding.UTF8.GetBytes(saltedPassword);
                var hashBytes = sha256.ComputeHash(passwordBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

    }
}
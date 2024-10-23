package middleware

import(
	"github.com/justinas/alice"
	"log"
	"net/http"
	"time"
	"strings"
	"github.com/ZaidKazi123/golang-csrf-project/server/middleware/myJwt"
	"github.com/ZaidKazi123/golang-csrf-project/server/templates"
	"github.com/ZaidKazi123/golang-csrf-project/db"
)

func NewHanlder() http.Handler{
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler)http.Handler{
	fn := func(w http.ResponseWriter, r *http.Request){
		defer func(){
			if err := recover(); err !=nil {
				log.Panic("Recovered! Panic:%+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServerHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler{
	fn := func(w http.ResponseWriter, r *http.Request){
		switch r.URL.Path{
		case "/restricted", "/logout", "/deleteUser":
			log.Println("In auth restricted section")

			AuthCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie{
				log.Println("Unauthorized attempt! no auth cookie")
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(401), 401)
				return
			}else if authErr != nil{
				log.Panic("panic: %+v", authErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			RefreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie{
				log.Println("Unauthorized attempt! no auth cookie")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)
				return
			}else if refreshErr != nil{
				log.Panic("panic: %+v", refreshErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			requestCsrfToken := grabCsrfFromReq(r)
			log.Println(requestCsrfToken)

			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
			if err != nil{
				if err.Error() == "Unauthorized"{
					long.Println("Unauthorized attepmt! JWT's not valid!")
					http.Error(w, http.StatusText(401), 401)
					return
				}else{
					log.Panic("err not nil")
					log.Panic("panic: %+v", err)
					http.Error(w, http.StatusText(500), 500)
				}
			}
			log.Println("Successfully created JWTs")

			w.Header().Set("Access-Control-Allow-Origin", "*")
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
		default:
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request){
	switch r.URL.Path{
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage(csrfSecret, "Hello Bro"))
	case "/login":
		switch r.Method{
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage(false, ""))
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			user, uuid, loginErr := db.LogUserIn(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"]), "")
			log.Println(user,uuid,loginErr)

			if loginErr != nil{
				w.WriteHeader(http.StatusUnauthorized)
			}else{
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, user.Role)
				if err!=nil{
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)

				w.WriteHeader((http.StatusOK))
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method{
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage(false, ""))
		case "POST":
			r.ParseForem()
			log.Println(r.Form)
			
			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
		if err == nil{
			w.WriteHeader(http.StatusUnauthorized)
		}else{
			role := "user"
			uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
			if err != nil{
				http.Error(w, http.StatusText(500), 500)
			}
			log.Println("uuid: " + uuid)

			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
			if err != nill{
				http.Error(w, http.StatusText(500), 500)
			}

			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
			w.WriteHeader(http.StatusOK)
		}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", 302)
	case "/deleteUser": 
		log.Println("Deleting the user")
		AuthCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie{
			log.Println("unauthorized attempt! no auth cookiue")
			nullifyTokenCookies(&w, r)
			http.Redirect(w, r, "/login", 302)
			return
		}else if authErr != nil{
			log.Panic("panic%+v", authErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		uuid, uuiderr := myJwt.GrabUUID(AuthCookie.Value)
		if uuiderr != nil{
			log.Panic("panic%+v", uuiderr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		db.DeleteUser(uuid)
		nullifyTokenCookies(&w, r)
		http.Redirect(w,r,"/register", 302)
	default:
		w.WriteHeader(http.StatusOK)
	}
	 
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request){
	authCookie := http.Cookie{
		Name:"AuthToken",
		Value:"",
		Expires:time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:"RefreshToken",
		Value:"",
		Expires:time.Now().Add(-1000 * time.Hour)
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie{
		return
	}else if refreshErr != nil{
		log.Panic("panic: %+v", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
	}
	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string){
	authCookie := http.Cookie{
		Name: "AuthToken",
		Value: authTokenString,
		HttpOnly: true
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie : http.Cookie{
		Name: "RefreshToken",
		Value: refreshTokenString,
		HttpOnly: true
	}
	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string{
	csrfFromFrom := r.FormValue("X-CSRF-Token")

	if csrfFromFrom != ""{
		return csrfFromFrom
	}else{
		return r.Header.GET("X-CSRF-Token")
	}
}
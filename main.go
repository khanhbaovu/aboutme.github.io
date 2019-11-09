package main

import (
//  "fmt"
  "net/http"
//  "github.com/gorilla/mux"
  "github.com/gorilla/sessions"
  "golang.org/x/crypto/bcrypt"
  "html/template"
  "log"
)

var (
  key = []byte("secret-key")
  store = sessions.NewCookieStore(key)
)

func PasswordHasher(password string) (string, error) {
  bytes, err := bcrypt.GenerateFromPassword([]byte(password),14)

  return string(bytes), err
}

func PasswordChecker(password, hash string) bool {
  err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

  return err == nil
}

func Login(w http.ResponseWriter, r *http.Request) {
  temp := template.Must(template.ParseFiles("templates/login.html"))

  authorName := "khanhbaovu"
  authorPassWord := "khanh02122000"
  hash,_ := PasswordHasher(authorPassWord)

  if r.Method == http.MethodPost {
    nameInput := r.FormValue("username")
    passInput := r.FormValue("password")

    check := PasswordChecker(passInput, hash)
    session,_ := store.Get(r,"cookie-name")

    if nameInput == authorName && check {

      session.Values["authenticated"] = true
      session.Save(r,w)

      http.Redirect(w, r, "/aboutme", http.StatusSeeOther)
    }else {
      session.Values["authenticated"] = false
      session.Save(r,w)

      http.Redirect(w,r,"/login",http.StatusUnauthorized)
      w.Write([]byte("<script>alert('Find the right username and password to login and know me')</script>"))
    }
    return
  }

  temp.Execute(w, nil)
}

func AboutMe(w http.ResponseWriter, r *http.Request) {

  if r.Method == http.MethodPost {
      http.Redirect(w,r,"/logout", http.StatusSeeOther)
      return
  }

  session,_ := store.Get(r, "cookie-name")

  if auth, ok := session.Values["authenticated"].(bool); auth && ok {
    temp := template.Must(template.ParseFiles("templates/index.html"))
    temp.Execute(w, nil)
    return
  }

  w.Write([]byte("<script>alert('You Need To Login To Know ME')</script>"))

}

func Logout(w http.ResponseWriter, r *http.Request) {
  session,_ := store.Get(r,"cookie-name")

  session.Values["authenticated"] = false

  session.Save(r,w)

  w.Write([]byte("<script>alert('You Logged Out!')</script>"))
}

func main() {

  http.HandleFunc("/login", Login)
  http.HandleFunc("/aboutme", AboutMe)
  http.HandleFunc("/logout", Logout)

  http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))

  log.Fatal(http.ListenAndServe(":8080", nil))
}

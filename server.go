package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type UserClaims struct {
	ID *User `json:"id"`
	jwt.StandardClaims
}

func InitServer() {
	r := gin.Default()
	r.LoadHTMLGlob("webpage/**/*.html")

	api := r.Group("/api")
	api.POST("/register", RegisterHandler)
	api.POST("/login", LoginHandler)
	r.Static("/webpage", "./webpage")
	r.GET("/", IndexPageHandler)
	r.GET("/register", RegisterPageHandler)
	r.GET("/login", LoginPageHandler)
	r.Run(":80")

}

func RegisterHandler(c *gin.Context) {

	username := c.PostForm("username")
	password := c.PostForm("password")

	if password == "" || username == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "missing form data",
		})
		return
	}

	err := RegisterUserDB(username, password)
	if err != nil {
		c.JSON(http.StatusNotAcceptable, gin.H{
			"message": "cannot register user",
		})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"message": "success",
	})
}

func LoginHandler(c *gin.Context) {

	username := c.PostForm("username")
	password := c.PostForm("password")

	id, err := LoginUserDB(username, password)

	if err != nil {
		c.JSON(401, gin.H{
			"message": "failed login",
		})
		return
	} else {
		claims := UserClaims{
			id,
			jwt.StandardClaims{
				ExpiresAt: 604800,
				Issuer:    "server",
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString([]byte(signToken))
		if err != nil {
			log.Println(err)
		}
		c.SetCookie("token", signed, 604800, "/", "localhost", true, false)
		c.JSON(http.StatusAccepted, gin.H{
			"message": "success",
			"token":   signed,
		})
	}
}

func IndexPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

func RegisterPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", nil)
}

func LoginPageHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

func TokenCheck(tokenString string) (*UserClaims, error) {
	claims := &UserClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(signToken), nil
	})

	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("ID token is invalid")
	}

	claims, ok := token.Claims.(*UserClaims)

	if !ok {
		return nil, fmt.Errorf("ID token valid but couldn't parse claims")
	}
	return claims, nil
}

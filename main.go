package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
	"github.com/ktm-m/playground-social-network-oauth/constant"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"log"
	"net/http"
	"os"
)

func main() {
	err := godotenv.Load("config/.env")
	if err != nil {
		log.Fatalln("cannot loan environment variables")
	}

	app := echo.New()
	app.Use(middleware.Logger())
	app.Use(middleware.Recover())

	v1Group := app.Group("/api/v1")
	lineGroup := v1Group.Group("/line")

	lineGroup.GET("/login", login)
	lineGroup.GET("/callback", callback)
	lineGroup.GET("/profile", profile)
	lineGroup.POST("/logout", logout)

	log.Fatalln(app.Start(fmt.Sprintf(":%s", os.Getenv("APP_PORT"))))
}

func generateState() (string, error) {
	b := make([]byte, 16)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

func buildLineAuthURL(lineAuthURL, channelID, redirectURI, state string) string {
	return fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&state=%s&scope=profile", lineAuthURL, channelID, redirectURI, state)
}

func login(c echo.Context) error {
	state, err := generateState()
	if err != nil {
		log.Println("cannot generate state", err.Error())
		return c.JSON(500, echo.Map{
			"message": "cannot generate state",
		})
	}

	return c.Redirect(
		http.StatusFound,
		buildLineAuthURL(constant.LINEAuthURL,
			os.Getenv("LINE_CHANNEL_ID"),
			os.Getenv("LINE_CHANNEL_REDIRECT_URI"),
			state))
}

func callback(c echo.Context) error {
	code := c.QueryParams().Get("code")
	if code == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "code is missing",
		})
	}

	client := resty.New()
	tokenResp := map[string]interface{}{}

	_, err := client.R().
		SetFormData(map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  os.Getenv("LINE_CHANNEL_REDIRECT_URI"),
			"client_id":     os.Getenv("LINE_CHANNEL_ID"),
			"client_secret": os.Getenv("LINE_CHANNEL_SECRET"),
		}).SetResult(&tokenResp).Post(constant.LINETokenURL)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "cannot exchange code to token",
		})
	}

	accessToken := tokenResp["access_token"].(string)
	refreshToken := tokenResp["refresh_token"].(string)

	return c.JSON(http.StatusOK, echo.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func profile(c echo.Context) error {
	accessToken := c.QueryParams().Get("access_token")
	if accessToken == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "access_token is required",
		})
	}

	client := resty.New()
	profileResp := map[string]interface{}{}
	_, err := client.R().
		SetAuthToken(accessToken).
		SetResult(&profileResp).
		Get(constant.LINEProfileURL)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "cannot get profile",
		})
	}

	return c.JSON(http.StatusOK, profileResp)
}

func logout(c echo.Context) error {
	accessToken := c.FormValue("access_token")
	if accessToken == "" {
		return c.JSON(http.StatusBadRequest, echo.Map{
			"message": "access_token is required",
		})
	}

	client := resty.New()
	resp, err := client.R().
		SetFormData(map[string]string{
			"access_token":  accessToken,
			"client_id":     os.Getenv("LINE_CHANNEL_ID"),
			"client_secret": os.Getenv("LINE_CHANNEL_SECRET"),
		}).Post(constant.LINERevokeURL)
	if err != nil || resp.StatusCode() != http.StatusOK {
		return c.JSON(http.StatusInternalServerError, echo.Map{
			"message": "cannot revoke token",
		})
	}

	return c.JSON(http.StatusOK, echo.Map{
		"message": "token has been revoked",
	})
}

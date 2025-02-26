package myJwt

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"time"

	"github.com/ZaidKazi123/golang-csrf-project/db"
	"github.com/ZaidKazi123/golang-csrf-project/db/models"
	jwt "github.com/dgrijalva/jwt-go"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath  = "keys/app.rsa.pub"
)

var (
	verifyKey = *rsa.PublicKey
	signKey   = *rsa.PrivateKey
)

func InitJWT() error {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}
	return nil
}

func CreateNewTokens(uuid string, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}

	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)
	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	return
}

func CheckAndRefreshTokens(oldAuthTokenString string, oldRefreshTokenString string, oldCrsfSecret string) (newAuthTokenString, newRefreshTokenString, newCrsfSecret string, err error) {
	if oldCrsfSecret == "" {
		log.Println("No CSRF token!")
		err = errors.New("Unauthorized")
		return
	}
	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}
	if oldCrsfSecret != authTokenClaims.Csrf {
		log.Println("CSRF token doesn't match jwt!")
		err = errors.New("Unauthorized")
		return
	}

	if authToken.Valid {
		log.Println("Auth token is valid")

		newCrsfSecret = authTokenClaims.Csrf
		newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
		newAuthTokenString = oldAuthTokenString
		return
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		log.Println("Auth token is not valid")
		if ve.Errors&(jwt.ValidErrorExpired) != 0 {
			log.Println("Auth token is expired")

			newAuthTokenString, newCsrfSecret, err = updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)

			if err != nil {
				return
			}
			newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
			if err != nil {
				return
			}

			newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCrsfSecret)
			return
		} else {
			log.Println("Error in Auth Token")
			err = errors.New("error in auth token")
			return
		}
	} else {
		log.Println("error in auth token")
		err = errors.New("error in auth token")
		return
	}

	err = errors.New("Unauthorized")
	return

}

func createAuthTokenString(uuid string, role string, csrfSecret string) (authTokenString, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExp,
		},
		role,
		csrfSecret,
	}
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	authTokenString, err = authJwt.SignedString(signKey)
	return
}

func createRefreshTokenString(uuid string, role string, csrfString string) (refreshTokenString string, err string) {
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        refreshJti,
			Subject:   uuid,
			ExpiresAt: refreshTokenExp,
		},
		role,
		csrfString,
	}
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RSA256"), refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func updateRefreshTokenExp(oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: refreshTokenExp,
		},
		oldRefreshTokenString.Role,
		oldRefreshTokenString.Csrf,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenString, err = refreshJwt.SignedString(signkey)
	return

}

func updateAuthTokenString(refreshTokenString string, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("error reading jwt claims")
		return
	}

	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id) {
		if refreshToken.Valid {
			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.token) (interface{}, error) {
				return verify, nil
			})

			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok {
				err = errors.New("error reading jwt calims")
				return
			}

			csrfSecret, err = models.GenerateCSRFSecret()

			if err != nil {
				return
			}

			createAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)
			return
		} else {
			log.Println("refresh token has expired")
			db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)
			err = errors.New("Unauthorized")
			return
		}
	} else {
		log.Println("refresh has been revoked")
		err = errors.New("Unauthorized")
		return
	}
}

func RevokeRefreshToken(refreshTokenString string) error {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if err != nil {
		return errors.New("Could not parse refresh token with claims")
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return errors.New("Could not read refresh token claims")
	}

	db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

	return nil
}

func updateRefreshTokenCsrf(oldRefreshTokenString string, newCsrfString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	oldrefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt,
		},
		oldrefreshTokenClaims.Role,
		newCsrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func GrabUUID(authTokenString string) (string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token, *jwt.Token) (interface{}, error) {
		return "", errors.New("Error fetching claims")
	})

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("error fetching claims")
	}

	return authTokenClaims.StandardClaims.Subject, nil
}

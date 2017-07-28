//package fidomds
package main

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
)

const FidoMDSUrl = "https://mds.fidoalliance.org"

const FidoRootCert = `-----BEGIN CERTIFICATE-----
MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG
A1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFk
YXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoX
DTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxs
aWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRS
b290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+
AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4ims
rfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYw
HwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAw
ZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciW
DcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XU
YjdBz56jSA==
-----END CERTIFICATE-----`

type StatusReportEntry struct {
	Status        string `json:"status"`
	URL           string `json:"url"`
	Certificate   string `json:"certificate"`
	EffectiveDate string `json:"effectiveDate"`
}

type MetadataTOCPayloadEntry struct {
	AAID                   string              `json:"aaid"`
	Hash                   string              `json:"hash"`
	URL                    string              `json:"url"`
	StatusReport           []StatusReportEntry `json:"statusReports"`
	TimeOfLastStatusChange string              `json:"timeOfLastStatusChange"`
}

type MetadataTOC struct {
	NextUpdate string `json:"nextUpdate"`
	No         int    `json:"no"`
	//nextUpdate string                    `json:"next-update"`
	Entries []MetadataTOCPayloadEntry `json:"entries"`
}

func (metadataTOC *MetadataTOC) Valid() error {
	return nil
}

func getMDSData() ([]byte, error) {
	resp, err := http.Get(FidoMDSUrl)
	if err != nil {
		log.Printf("%s", err)
		return nil, err
	}
	defer resp.Body.Close()
	// check return value here!
	if resp.StatusCode != 200 {
		err := errors.New("Unexpected status code")
		log.Println("Unexpected status code", resp.StatusCode)
		return nil, err
	}

	return ioutil.ReadAll(resp.Body)
}

func main() {
	log.Println("vim-go")

	rawMDSData, err := getMDSData()
	if err != nil {
		panic(err)
	}
	//log.Printf("%s", rawMDSData)
	tokenString := string(rawMDSData[:])
	var metadataToc MetadataTOC
	token, err := jwt.ParseWithClaims(tokenString, &metadataToc, func(token *jwt.Token) (interface{}, error) {
		//token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})

	if token.Valid {
		fmt.Println("You look nice today")
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			fmt.Println("That's not even a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			fmt.Println("Timing is everything")
		} else {
			fmt.Println("Couldn't handle this token (have ve): %+v\n %+v", err, token.Header, token.Claims)
		}
	} else {
		fmt.Println("Couldn't handle this token:", err)
	}
	log.Printf("parsed=%+v", metadataToc)
	log.Printf("done")
}

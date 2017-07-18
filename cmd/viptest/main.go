package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/Symantec/keymaster/lib/vip"
	"io/ioutil"
	"os"
)

var (
	certFilename = flag.String("cert", "", "The filename of the certificate")
	certKey      = flag.String("key", "", "the key for the cert")
	targetUrl    = flag.String("targetUrl", "https://vipservices-auth.verisign.com/val/soap", "the key for the cert")
	tokenID      = flag.String("tokenid", "", "The tokenID to test")
	otpValue     = flag.Int("OTP", 1234, "The otp Value")
	debug        = flag.Bool("debug", false, "Enable debug messages to console")
)

func exitsAndCanRead(fileName string, description string) ([]byte, error) {
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return nil, err
	}
	buffer, err := ioutil.ReadFile(fileName)
	if err != nil {
		err = errors.New("cannot read " + description + "file")
		return nil, err
	}
	return buffer, err
}

func main() {
	flag.Parse()
	fmt.Println("vim-go")
	certPem, err := exitsAndCanRead(*certFilename, "certificate file")
	if err != nil {
		panic(err)
	}
	keyPem, err := exitsAndCanRead(*certKey, "key file file")
	if err != nil {
		panic(err)
	}

	vipClient, err := vip.NewClient(certPem, keyPem)
	if err != nil {
		panic(err)
	}
	vipClient.VipServicesURL = *targetUrl
	ok, err := vipClient.VerifySingleToken(*tokenID, *otpValue)
	if err != nil {
		panic(err)
	}
	fmt.Printf("result=%d", ok)
	fmt.Println("done")

}

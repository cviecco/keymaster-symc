package main

import (
	//"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"github.com/Symantec/keymaster/lib/vip"
	"io/ioutil"
	"log"
	"os"
	"os/user"
)

const ExampleUserInfoResponse = `<?xml version="1.0"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Body>
    <GetUserInfoResponse xmlns="https://schemas.symantec.com/vip/2011/04/vipuserservices">
      <requestId>258aaa0361ea</requestId>
      <status>0000</status>
      <statusMessage>Success</statusMessage>
      <userId>username</userId>
      <userCreationTime>2016-05-25T18:40:29.747Z</userCreationTime>
      <userStatus>ACTIVE</userStatus>
      <numBindings>1</numBindings>
      <credentialBindingDetail>
        <credentialId>AVTXXXXXXX</credentialId>
        <credentialType>STANDARD_OTP</credentialType>
        <credentialStatus>ENABLED</credentialStatus>
        <bindingDetail>
          <bindStatus>ENABLED</bindStatus>
          <friendlyName>symentec-hw1</friendlyName>
          <lastBindTime>2016-06-03T19:58:32.373Z</lastBindTime>
          <lastAuthnTime>2017-08-03T21:58:22.090Z</lastAuthnTime>
          <lastAuthnId>484374FC7EB7AA12</lastAuthnId>
        </bindingDetail>
      </credentialBindingDetail>
      <credentialBindingDetail>
        <credentialId>AVTYYYYYYY</credentialId>
        <credentialType>STANDARD_OTP</credentialType>
        <credentialStatus>ENABLED</credentialStatus>
        <bindingDetail>
          <bindStatus>ENABLED</bindStatus>
          <friendlyName>symentec-hw2</friendlyName>
          <lastBindTime>2016-06-03T19:58:32.373Z</lastBindTime>
          <lastAuthnTime>2017-08-03T21:58:22.090Z</lastAuthnTime>
          <lastAuthnId>484374FC7EB7AA12</lastAuthnId>
        </bindingDetail>
      </credentialBindingDetail> 
    </GetUserInfoResponse>
  </S:Body>
</S:Envelope>`

var (
	certFilename = flag.String("cert", "cert.pem", "The filename of the certificate")
	certKey      = flag.String("key", "key.pem", "the key for the cert")
	targetUrl    = flag.String("targetUrl", "https://vipservices-auth.verisign.com/val/soap", "the key for the cert")
	tokenID      = flag.String("tokenid", "", "The tokenID to test")
	otpValue     = flag.Int("OTP", 0, "The otp Value")
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

	usr, err := user.Current()
	if err != nil {
		log.Printf("cannot get current user info")
		log.Fatal(err)
	}
	userName := usr.Username

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

	valid, err := vipClient.ValidateUserOTP(userName, *otpValue)
	if err != nil {
		panic(err)
	}
	fmt.Printf("valid=%d", valid)
	fmt.Println("done")

}

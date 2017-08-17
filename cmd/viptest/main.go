package main

import (
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"github.com/Symantec/keymaster/lib/vip"
	"io/ioutil"
	"os"
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
    </GetUserInfoResponse>
  </S:Body>
</S:Envelope>`

var (
	certFilename = flag.String("cert", "cert.pem", "The filename of the certificate")
	certKey      = flag.String("key", "key.pem", "the key for the cert")
	targetUrl    = flag.String("targetUrl", "https://vipservices-auth.verisign.com/val/soap", "the key for the cert")
	tokenID      = flag.String("tokenid", "", "The tokenID to test")
	otpValue     = flag.Int("OTP", 1234, "The otp Value")
	debug        = flag.Bool("debug", false, "Enable debug messages to console")
)

type vipResponseBindingDetail struct {
	ReasonCode    string `xml:"bindStatus,omitempty"`
	FriendlyName  string `xml:"friendlyName,omitempty"`
	LastBindTime  string `xml:"lastBindTime,omitempty"`
	LastAuthnTime string `xml:"lastAuthnTime,omitempty"`
	LastAuthnId   string `xml:"lastAuthnId,omitempty"`
}
type vipResponseCredentialBindingDetail struct {
	CredentialId     string                   `xml:"credentialId,omitempty"`
	CredentialType   string                   `xml:"credentialType,omitempty"`
	CredentialStatus string                   `xml:"credentialStatus,omitempty"`
	BindingDetail    vipResponseBindingDetail `xml:"bindingDetail"`
}

type vipResponseGetUserInfo struct {
	RequestId               string                               `xml:"requestId"`
	Status                  string                               `xml:"status"`
	StatusMessage           string                               `xml:"statusMessage"`
	UserId                  string                               `xml:"userId"`
	UserCreationTime        string                               `xml:"userCreationTime"`
	UserStatus              string                               `xml:"userStatus"`
	NumBindings             string                               `xml:"numBindings"`
	CredentialBindingDetail []vipResponseCredentialBindingDetail `xml:"credentialBindingDetail"`
}

type userInfoResponseBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipResponseGetUserInfo vipResponseGetUserInfo `xml:"GetUserInfoResponse"`
	}
}

func parseUserInfoResponse() {
	var response userInfoResponseBody
	err := xml.Unmarshal([]byte(ExampleUserInfoResponse), &response)
	//err = xml.Unmarshal(responseBytes, &response)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Printf("%+v", response)
}

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
	parseUserInfoResponse()

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

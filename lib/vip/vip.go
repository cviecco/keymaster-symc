package vip

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"text/template"
	"time"

	"github.com/Symantec/keymaster/lib/util"
)

// The symantec VIP endpoint is very specific on namespaces, and golang's
// XML package is not very good with marshaling namespaces thus we will write
// requests using the text template. but parse them using the xml library
type vipValidateRequest struct {
	RequestId string `xml:"RequestId,attr"`
	TokenId   string `xml:"TokenId"`
	OTP       int    `xml:"OTP`
}

type validateRequestBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipValidateRequest vipValidateRequest `xml:"Validate"`
	}
}

const validateRequestTemplate = `<?xml version="1.0" encoding="UTF-8" ?> <SOAP-ENV:Envelope
        xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:ns3="http://www.w3.org/2000/09/xmldsig#"
        xmlns:ns1="http://www.verisign.com/2006/08/vipservice">
        <SOAP-ENV:Body>
                <ns1:Validate Version="2.0" Id="{{.RequestId}}"> 
                     <ns1:TokenId>{{.TokenId}}</ns1:TokenId> 
                     <ns1:OTP>{{.OTP}}</ns1:OTP>
                </ns1:Validate>
        </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`

type vipResponseStatus struct {
	ReasonCode    string `xml:"ReasonCode,omitempty" json:"ReasonCode,omitempty"`
	StatusMessage string `xml:"StatusMessage,omitempty" json:"StatusMessage,omitempty"`
}

type vipValidateResponse struct {
	RequestId string            `xml:"RequestId,attr"`
	Version   string            `xml:"Version,attr"`
	Status    vipResponseStatus `xml:"Status"`
}

type validateResponseBody struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		VipValidateResponse vipValidateResponse `xml:"ValidateResponse"`
	}
}

type vipUserInfoRequest struct {
	RequestId string `xml:"requestId`
	UserId    string `xml:"userId"`
}

const userInfoRequestTemplate = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vip="https://schemas.symantec.com/vip/2011/04/vipuserservices">
   <soapenv:Header/>
   <soapenv:Body>
      <vip:GetUserInfoRequest>
         <vip:requestId>{{.RequestId}}</vip:requestId>
         <vip:userId>{{.UserId}}</vip:userId>
         <!--Optional:-->
         <vip:iaInfo>false</vip:iaInfo>
         <!--Optional:-->
         <vip:includePushAttributes>true</vip:includePushAttributes>
      </vip:GetUserInfoRequest>
   </soapenv:Body>
</soapenv:Envelope>`

const exampleUserInfoResponse = `<?xml version="1.0"?>
<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
  <S:Body>
    <GetUserInfoResponse xmlns="https://schemas.symantec.com/vip/2011/04/vipuserservices">
      <requestId>258aaa0361ea</requestId>
      <status>0000</status>
      <statusMessage>Success</statusMessage>
      <userId>camilo_viecco1</userId>
      <userCreationTime>2016-05-25T18:40:29.747Z</userCreationTime>
      <userStatus>ACTIVE</userStatus>
      <numBindings>1</numBindings>
      <credentialBindingDetail>
        <credentialId>AVT807113441</credentialId>
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

/*
type userInfoBindingDetail {
}
*/

type Client struct {
	Cert               tls.Certificate
	VipServicesURL     string
	VipUserServicesURL string
	RootCAs            *x509.CertPool
}

///

func NewClient(certPEMBlock, keyPEMBlock []byte) (client Client, err error) {

	client.Cert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return client, err
	}
	//This is the production url for vipservices
	client.VipServicesURL = "https://vipservices-auth.verisign.com/val/soap"
	client.VipUserServicesURL = "https://userservices-auth.vip.symantec.com/vipuserservices/QueryService_1_7"
	return client, nil
}

func (client *Client) postBytesVip(data []byte, targetURL string, contentType string) ([]byte, error) {
	//two steps... convert data into post data!
	req, err := util.CreateSimpleDataBodyRequest("POST", targetURL, data, contentType)
	if err != nil {
		return nil, err
	}
	// make client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{client.Cert},
		RootCAs:      client.RootCAs,
		MinVersion:   tls.VersionTLS12}

	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	postResponse, err := httpClient.Do(req)
	if err != nil {
		log.Printf("got error from req")
		log.Println(err)
		// TODO: differentiate between 400 and 500 errors
		// is OK to fail.. try next
		return nil, err
	}
	defer postResponse.Body.Close()
	if postResponse.StatusCode != 200 {
		log.Printf("got error from login call %s", postResponse.Status)
		return nil, err
	}
	return ioutil.ReadAll(postResponse.Body)
}

func (client *Client) postBytesVipServices(data []byte) ([]byte, error) {
	return client.postBytesVip(data, client.VipServicesURL, "application/xml")
}

func (client *Client) postBytesUserServices(data []byte) ([]byte, error) {
	return client.postBytesVip(data, client.VipUserServicesURL, "text/xml")
}

// The response string is only to have some sort of testing
func (client *Client) VerifySingleToken(tokenID string, tokenValue int) (bool, error) {
	validateRequest := vipValidateRequest{RequestId: "12345",
		TokenId: tokenID, OTP: tokenValue}
	tmpl, err := template.New("validate").Parse(validateRequestTemplate)
	if err != nil {
		panic(err)
	}
	var requestBuffer bytes.Buffer

	//err = tmpl.Execute(os.Stdout, validateRequest)
	err = tmpl.Execute(&requestBuffer, validateRequest)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nbuffer='%s'\n", requestBuffer.String())
	responseBytes, err := client.postBytesVipServices(requestBuffer.Bytes())
	if err != nil {
		return false, err
	}
	var response validateResponseBody
	//err = xml.Unmarshal([]byte(responseText), &response)
	err = xml.Unmarshal(responseBytes, &response)
	if err != nil {
		fmt.Print(err)
	}
	fmt.Printf("%+v", response)
	output, err := xml.MarshalIndent(&response, " ", "    ")
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}

	//os.Stdout.Write(output)
	fmt.Println(output)
	// {XMLName:{Space:http://schemas.xmlsoap.org/soap/envelope/ Local:Envelope} Body:{VipValidateResponse:{RequestId:12345 Version:2.0 Status:{ReasonCode:0000 StatusMessage:Success}}}}
	switch response.Body.VipValidateResponse.Status.ReasonCode {
	case "0000":
		return true, nil
	default:
		return false, nil
	}
	panic("should never have reached this point")
}
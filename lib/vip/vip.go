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

type Client struct {
	Cert           tls.Certificate
	VipServicesURL string
	RootCAs        *x509.CertPool
}

///

func NewClient(certPEMBlock, keyPEMBlock []byte) (client Client, err error) {

	client.Cert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return client, err
	}
	//This is the production url for vipservices
	client.VipServicesURL = "https://vipservices-auth.verisign.com/val/soap"

	return client, nil
}

func (client *Client) postBytesVipServices(data []byte) ([]byte, error) {
	//two steps... convert data into post data!
	req, err := util.CreateSimpleDataBodyRequest("POST", client.VipServicesURL, data, "application/xml")
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

	return false, nil
}

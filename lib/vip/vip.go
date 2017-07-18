package vip

import (
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"os"
	"text/template"
)

// The symantec VIP endpoint is very specific on namespaces, and golang's
// XML package is not very good with marshaling namespaces thus we will write
// requests using the text template.

// These two are actual working values for the validate api
/*
const exampleResponseValueText = `<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">
    <Body>
        <ValidateResponse RequestId="CDCE1500" Version="2.0" xmlns="http://www.verisign.com/2006/08/vipservice">
            <Status>
                <ReasonCode>49B5</ReasonCode>
                <StatusMessage>Failed with an invalid OTP</StatusMessage>
            </Status>
        </ValidateResponse>
    </Body>
</Envelope>`

const exampleRequestValueText = `<?xml version="1.0" encoding="UTF-8" ?> <SOAP-ENV:Envelope
        xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:ns3="http://www.w3.org/2000/09/xmldsig#"
        xmlns:ns1="http://www.verisign.com/2006/08/vipservice">
        <SOAP-ENV:Body>
                <ns1:Validate Version="2.0" Id="CDCE1500"> <ns1:TokenId>AVT333666999</ns1:TokenId> <ns1:OTP>534201</ns1:OTP>
                </ns1:Validate>
        </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`
*/
//////////
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

// The response string is only to have some sort of testing
func (client *Client) VerifySingleToken(tokenID string, tokenValue int, responseText string) (bool, error) {
	validateRequest := vipValidateRequest{RequestId: "12345",
		TokenId: tokenID, OTP: tokenValue}
	tmpl, err := template.New("validate").Parse(validateRequestTemplate)
	if err != nil {
		panic(err)
	}

	err = tmpl.Execute(os.Stdout, validateRequest)
	if err != nil {
		panic(err)
	}
	var response validateResponseBody
	err = xml.Unmarshal([]byte(responseText), &response)
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

/*
func testResponse() {
	var response validateResponseBody
	err := xml.Unmarshal([]byte(exampleResponseValueText), &response)
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
}
*/

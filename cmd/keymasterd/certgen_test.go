package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Symantec/keymaster/lib/certgen"
	"github.com/Symantec/keymaster/lib/webapi/v0/proto"
)

const testSignerX509Cert = `-----BEGIN CERTIFICATE-----
MIIDeTCCAmGgAwIBAgIJAMSRCvyhZiyzMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNV
BAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxFDASBgNVBAoMC0V4YW1wbGUu
Y29tMRcwFQYDVQQDDA5FeGFtcGxlIElzc3VlcjAeFw0xNzA0MjYxODAyMzJaFw0y
NzA0MjQxODAyMzJaMFMxCzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENp
dHkxFDASBgNVBAoMC0V4YW1wbGUuY29tMRcwFQYDVQQDDA5FeGFtcGxlIElzc3Vl
cjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9ieOuCqGGzgzCG7ZE1
efIOv9EE3VCGIDsJ8z3WjDVbQjsU4kAyFhG86r9RxD/YX87mkih1B7P/dXuCY9qm
YIUsDxyxu0ys7vvwkSvbGvY76BhFcYOso4mz53Uxri1abWQnDiHBxF1Yj+Iq2iOn
cm4hg5ZnhfdlkCXSO5eBLIOFuFqdeyRVjR28pSqBQdH3tm+Kuac2lzAcDbnuASir
7mudTQXLUcuC2WMIhr1SaZRG4wVO78AgEtF+Ju9stibyqIPfx3xiqNq2fbHtMBXv
ZjJI49MLipA4fdaTs7AWf9D1tMx3ItqvciVcRdG+NXvfq2l2vJL0Y8RexBALlK/T
r9sCAwEAAaNQME4wHQYDVR0OBBYEFP9MhquAFRFLT7fzbru/pHUZd7izMB8GA1Ud
IwQYMBaAFP9MhquAFRFLT7fzbru/pHUZd7izMAwGA1UdEwQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBAAS+HXeUf/WG6g2AbNvd3F+8KkoWmNnRZ8OHuXYQxSQeXHon
Bi0CAc7BZo43n9GSOy4mW0F6Z3JVkK06gH3pFRoKkqqpzk5WaCIYoofRRIOsF/l6
tng3ucauQ3wYGftwid623D6nnbkhPj0jmTyGD6d772dueWEneR2JcN/5G7Xf8HEl
a0fmpm1BG1ZrT2Vp4cb50VeFH+oZn9UW6j+w3Lx4D6pwJvJ11MFjkIfw7Q1hl0j9
Unc9jsYhX7DR3SV8vcFqduUmSH8vdc/zJEk76T2D+qe1aWqtr84QpxXBTrIKvSXD
igkmavdG2gu3SpbFzNxuVCrxQ88Kte0xYJTe7vY=
-----END CERTIFICATE-----`

const testDuration = time.Duration(120 * time.Second)

/// X509section (this is from certgen TODO: make public)
func getPubKeyFromPem(pubkey string) (pub interface{}, err error) {
	block, rest := pem.Decode([]byte(pubkey))
	if block == nil || block.Type != "PUBLIC KEY" {
		err := errors.New(fmt.Sprintf("Cannot decode user public Key '%s' rest='%s'", pubkey, string(rest)))
		if block != nil {
			err = errors.New(fmt.Sprintf("public key bad type %s", block.Type))
		}
		return nil, err
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func setupX509Generator(t *testing.T) (interface{}, *x509.Certificate, crypto.Signer) {
	userPub, err := getPubKeyFromPem(testUserPEMPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	//caPriv, err := getPrivateKeyFromPem(testSignerPrivateKey)
	caPriv, err := certgen.GetSignerFromPEMBytes([]byte(testSignerPrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	caCertBlock, _ := pem.Decode([]byte(testSignerX509Cert))
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return userPub, caCert, caPriv
}

func TestSuccessFullSigningX509IPCert(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	state.Config.Base.AllowedAuthBackendsForCerts = append(state.Config.Base.AllowedAuthBackendsForCerts, proto.AuthTypeIPCertificate)

	// Get request
	req, err := createKeyBodyRequest("POST", "/certgen/username?type=x509", testUserPEMPublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = checkRequestHandlerCode(req, state.certGenHandler, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// now we add an ipcert to the request

	userPub, caCert, caPriv := setupX509Generator(t)
	netblock := net.IPNet{
		IP:   net.ParseIP("127.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblock2 := net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblockList := []net.IPNet{netblock, netblock2}
	derCert, err := certgen.GenIPRestrictedX509Cert("username", userPub, caCert, caPriv, netblockList, testDuration, nil, nil)

	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1:12345"
	var fakePeerCertificates []*x509.Certificate
	var fakeVerifiedChains [][]*x509.Certificate
	fakePeerCertificates = append(fakePeerCertificates, cert)
	fakeVerifiedChains = append(fakeVerifiedChains, fakePeerCertificates)
	connectionState := &tls.ConnectionState{
		VerifiedChains:   fakeVerifiedChains,
		PeerCertificates: fakePeerCertificates}
	req.TLS = connectionState

	// Will fail due to bad username
	_, err = checkRequestHandlerCode(req, state.certGenHandler, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
	// Now add username to the set of valid users to get certs from
	state.Config.Base.AutomationUsers = append(state.Config.Base.AutomationUsers, "username")
	_, err = checkRequestHandlerCode(req, state.certGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	//TODO check return content

	//now test with failure
	req.RemoteAddr = "192.168.255.255:12345"
	_, err = checkRequestHandlerCode(req, state.certGenHandler, http.StatusUnauthorized)
	if err != nil {
		t.Fatal(err)
	}
}

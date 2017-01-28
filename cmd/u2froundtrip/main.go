package main

import (
	"bytes"
	"crypto/rand"
	//"crypto/tls"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"net/http/httptest"

	//client side:
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"

	//server side:
	"github.com/tstranex/u2f"
)

const appID = "https://localhost:3483"

var trustedFacets = []string{appID}

// Normally these state variables would be stored in a database.
// For the purposes of the demo, we just store them in memory.
var challenge *u2f.Challenge

var registrations []u2f.Registration
var counter uint32

/// examples:
const clientDataExample = `{"typ":"navigator.id.finishEnrollment","challenge":"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo","cid_pubkey":{"kty":"EC","crv":"P-256","x":"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8","y":"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4"},"origin":"http://example.com"}`

const ClientDataRegistrationTypeValue = "navigator.id.finishEnrollment"

func registerRequest(w http.ResponseWriter, r *http.Request) {
	c, err := u2f.NewChallenge(appID, trustedFacets)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	challenge = c
	req := u2f.NewWebRegisterRequest(c, registrations)

	log.Printf("registerRequest: %+v", req)
	json.NewEncoder(w).Encode(req)
}

func registerResponse(w http.ResponseWriter, r *http.Request) {
	var regResp u2f.RegisterResponse
	if err := json.NewDecoder(r.Body).Decode(&regResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	if challenge == nil {
		http.Error(w, "challenge not found", http.StatusBadRequest)
		return
	}

	reg, err := u2f.Register(regResp, *challenge, &u2f.Config{SkipAttestationVerify: true})
	if err != nil {
		log.Printf("u2f.Register error: %v", err)
		http.Error(w, "error verifying response", http.StatusInternalServerError)
		return
	}

	registrations = append(registrations, *reg)
	counter = 0

	log.Printf("Registration success: %+v", reg)
	w.Write([]byte("success"))
}

func signRequest(w http.ResponseWriter, r *http.Request) {
	if registrations == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	c, err := u2f.NewChallenge(appID, trustedFacets)
	if err != nil {
		log.Printf("u2f.NewChallenge error: %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	challenge = c

	req := c.SignRequest(registrations)

	log.Printf("Sign request: %+v", req)
	json.NewEncoder(w).Encode(req)
}

func signResponse(w http.ResponseWriter, r *http.Request) {
	var signResp u2f.SignResponse
	if err := json.NewDecoder(r.Body).Decode(&signResp); err != nil {
		http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("signResponse: %+v", signResp)

	if challenge == nil {
		http.Error(w, "challenge missing", http.StatusBadRequest)
		return
	}
	if registrations == nil {
		http.Error(w, "registration missing", http.StatusBadRequest)
		return
	}

	var err error
	for _, reg := range registrations {
		newCounter, authErr := reg.Authenticate(signResp, *challenge, counter)
		if authErr == nil {
			log.Printf("newCounter: %d", newCounter)
			counter = newCounter
			w.Write([]byte("success"))
			return
		}
	}

	log.Printf("VerifySignResponse error: %v", err)
	http.Error(w, "error verifying response", http.StatusInternalServerError)
}

func prefilght() {
	exampleSum1 := sha256.Sum256([]byte(clientDataExample))
	log.Printf("exampleSum=%s\n", hex.EncodeToString(exampleSum1[:]))
}

func main() {
	prefilght()

	devices, err := u2fhid.Devices()
	if err != nil {
		log.Fatal(err)
	}
	if len(devices) == 0 {
		log.Fatal("no U2F tokens found")
	}

	d := devices[0]
	log.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x", d.Manufacturer, d.Product, d.ProductID, d.VendorID)

	dev, err := u2fhid.Open(d)
	if err != nil {
		log.Fatal(err)
	}
	t := u2ftoken.NewToken(dev)

	version, err := t.Version()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("version:", version)

	// Now lest actually make a real register request:
	webReq, err := http.NewRequest("GET", appID, nil)
	if err != nil {
		log.Fatal(err)
		//return nil, err
	}
	rr := httptest.NewRecorder()
	registerRequest(rr, webReq)
	log.Printf("request=%s\n", rr.Body.String()) // rr.Body is a *bytes.Buffer

	var webRegRequest u2f.WebRegisterRequest
	err = json.Unmarshal([]byte(rr.Body.String()), &webRegRequest)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("back on client%+v\n", webRegRequest)

	// check for version match between token and webRegRequest?... Now actually build the suff

	tokenRegistrationClientData := u2f.ClientData{Typ: ClientDataRegistrationTypeValue, Challenge: webRegRequest.RegisterRequests[0].Challenge, Origin: webRegRequest.AppID}
	tokenRegistrationBuf := new(bytes.Buffer)
	err = json.NewEncoder(tokenRegistrationBuf).Encode(tokenRegistrationClientData)
	if err != nil {
		log.Fatal(err)
	}

	// Now we build the challenge and client data from the rr body

	challenge := make([]byte, 32)
	app := make([]byte, 32)
	//io.ReadFull(rand.Reader, challenge)
	//io.ReadFull(rand.Reader, app)
	reqAppID := sha256.Sum256([]byte(webRegRequest.AppID))
	reqChallenge := sha256.Sum256(tokenRegistrationBuf.Bytes())
	app = reqAppID[:]
	challenge = reqChallenge[:]

	var res []byte
	log.Println("registering, provide user presence")
	for {
		res, err = t.Register(u2ftoken.RegisterRequest{Challenge: reqChallenge[:], Application: reqAppID[:]})
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			log.Fatal(err)
		}
		break
	}
	var registrationRequestResponse u2f.RegisterResponse
	registrationRequestResponse.RegistrationData = base64.RawURLEncoding.EncodeToString(res)
	registrationRequestResponse.Version = version
	registrationRequestResponse.ClientData = base64.RawURLEncoding.EncodeToString(tokenRegistrationBuf.Bytes())

	log.Printf("registered: %x", res)
	res = res[66:]
	khLen := int(res[0])
	res = res[1:]
	keyHandle := res[:khLen]
	log.Printf("key handle: %x", keyHandle)

	dev.Close()

	log.Printf("%+v\n", registrationRequestResponse)

	webRegRequestBuf := &bytes.Buffer{}
	err = json.NewEncoder(webRegRequestBuf).Encode(registrationRequestResponse)
	if err != nil {
		log.Fatal(err)
	}

	webRegRequest2, err := http.NewRequest("POST", "/someurl", webRegRequestBuf)
	if err != nil {
		log.Fatal(err)
	}
	rr2 := httptest.NewRecorder()
	registerResponse(rr2, webRegRequest2)
	log.Printf("request=%s\n", rr2.Body.String()) // rr.Body is a *bytes.Buffer

	///////////////////registration done!

	httpSignRequest, err := http.NewRequest("GET", "/someurl", nil)
	if err != nil {
		log.Fatal(err)
	}
	rr3 := httptest.NewRecorder()
	signRequest(rr3, httpSignRequest)
	log.Printf("signRequest=%s\n", rr3.Body.String()) // rr.Body is a *bytes.Buffer

	var webSignRequest u2f.WebSignRequest
	if err := json.NewDecoder(rr3.Body).Decode(&webSignRequest); err != nil {
		//http.Error(w, "invalid response: "+err.Error(), http.StatusBadRequest)
		//        return
		log.Fatal(err)
	}
	log.Printf("%+v\n", webSignRequest)

	////
	log.Println("reconnecting to device in 3 seconds...")
	time.Sleep(3 * time.Second)

	devices, err = u2fhid.Devices()
	if err != nil {
		log.Fatal(err)
	}
	d = devices[0]
	dev, err = u2fhid.Open(d)
	if err != nil {
		log.Fatal(err)
	}
	t = u2ftoken.NewToken(dev)

	io.ReadFull(rand.Reader, challenge)
	req := u2ftoken.AuthenticateRequest{
		Challenge:   challenge,
		Application: app,
		KeyHandle:   keyHandle,
	}
	if err := t.CheckAuthenticate(req); err != nil {
		log.Fatal(err)
	}

	//io.ReadFull(rand.Reader, challenge)
	log.Println("authenticating, provide user presence")
	for {
		res, err := t.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			log.Fatal(err)
		}
		log.Printf("counter = %d, signature = %x", res.Counter, res.Signature)
		break
	}

	if dev.CapabilityWink {
		log.Println("testing wink in 2s...")
		time.Sleep(2 * time.Second)
		if err := dev.Wink(); err != nil {
			log.Fatal(err)
		}
		time.Sleep(2 * time.Second)
	} else {
		log.Println("no wink capability")
	}
}

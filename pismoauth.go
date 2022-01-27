package pismoauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HeaderName         string
	PismoPublicKeysURL string
	MaxAgeTime         time.Duration
}

func CreateConfig() *Config {
	return &Config{
		HeaderName:         "X-PismoAuth",
		PismoPublicKeysURL: "https://sandbox.pismolabs.io/robot/v1/metadata/x509/pismolabs@dev-gke-7a65.iam.gserviceaccount.com",
	}
}

type PismoAuth struct {
	next               http.Handler
	headerName         string
	name               string
	pismoPublicKeysURL string
	keys               map[string]string
	maxAgeTime         time.Duration
}

type JWT struct {
	Plaintext []byte
	Signature []byte
	Header    JwtHeader
	Payload   map[string]interface{}
}

type JwtHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Cty  string   `json:"cty"`
	Crit []string `json:"crit"`
}

/*
 * Cria a instância do pluguin no contexto do traefik
 */
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.PismoPublicKeysURL) == 0 {
		return nil, fmt.Errorf("PismoPublicKeysURL não pode ser vazio")
	}

	pismoAuth := &PismoAuth{
		next:               next,
		name:               name,
		headerName:         config.HeaderName,
		pismoPublicKeysURL: config.PismoPublicKeysURL,
		maxAgeTime:         config.MaxAgeTime,
	}
	go pismoAuth.backgroundRefresh()

	return pismoAuth, nil
}

func (pismoAuth *PismoAuth) backgroundRefresh() {
	for {
		FetchKeys(pismoAuth)

		time.Sleep(pismoAuth.maxAgeTime * time.Second)
	}
}

func FetchKeys(pismoAuth *PismoAuth) {
	response, err := http.Get(pismoAuth.pismoPublicKeysURL)
	if err != nil {
		panic(err)
	}
	json.NewDecoder(response.Body).Decode(&pismoAuth.keys)

	// @todo Ignorar o case do header Cache-Control
	var cacheControl string = response.Header["Cache-Control"][0]
	var cacheControlData []string = strings.Split(cacheControl, ",")
	for _, value := range cacheControlData {
		if strings.Contains(strings.ToUpper(value), "MAX-AGE") {
			var maxAge = strings.Split(value, "=")[1] // Time in seconds

			ageTime, _ := strconv.Atoi(maxAge)
			pismoAuth.maxAgeTime = time.Duration(ageTime * int(time.Second))
		}
	}
}

/*
 * Função que receberá toda requisição contendo as credenciais da pismo
 */
func (pismoAuth *PismoAuth) ServeHTTP(rw http.ResponseWriter, request *http.Request) {
	if err := CheckToken(request, pismoAuth); err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}

	pismoAuth.next.ServeHTTP(rw, request)
}

func CheckToken(request *http.Request, pismoAuth *PismoAuth) error {
	jwtToken, err := pismoAuth.extractToken(request)
	if err != nil {
		return err
	}

	if jwtToken != nil {
		if err = pismoAuth.verifyToken(jwtToken); err != nil {
			return err
		}
	}
	return nil
}

func (pismoAuth *PismoAuth) extractToken(request *http.Request) (*JWT, error) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		return nil, nil
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, nil
	}
	parts := strings.Split(auth[7:], ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	jwtToken := JWT{
		Plaintext: []byte(auth[7 : len(parts[0])+len(parts[1])+8]),
		Signature: signature,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(payload, &jwtToken.Payload)
	if err != nil {
		return nil, err
	}
	return &jwtToken, nil
}

func (pismoAuth *PismoAuth) verifyToken(jwtToken *JWT) error {
	key, ok := pismoAuth.keys[jwtToken.Header.Kid]
	if !ok {
		// retornar um erro de chaves não encontradas
	}

	a, ok := tokenAlgorithms[jwtToken.Header.Alg]
	if !ok {
		return fmt.Errorf("unknown JWS algorithm: %s", jwtToken.Header.Alg)
	}
	return a.verify(key, a.hash, jwtToken.Plaintext, jwtToken.Signature)
}

/*
 * Algoritimos de validação do token
 */
type tokenVerifyFunction func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error
type tokenVerifyAsymmetricFunction func(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error

type tokenAlgorithm struct {
	hash   crypto.Hash
	verify tokenVerifyFunction
}

var tokenAlgorithms = map[string]tokenAlgorithm{
	"RS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPKCS)},
}

func verifyAsymmetric(verify tokenVerifyAsymmetricFunction) tokenVerifyFunction {
	return func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error {
		h := hash.New()
		_, err := h.Write(payload)
		if err != nil {
			return err
		}
		return verify(key, hash, h.Sum([]byte{}), signature)
	}
}

func verifyRSAPKCS(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error {
	keyString, _ := key.(string)
	pubBlock, _ := pem.Decode([]byte(keyString))

	cert, err := x509.ParseCertificate(pubBlock.Bytes)
	if err != nil {
	}
	pk, _ := cert.PublicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pk, hash, digest, signature); err != nil {
		return fmt.Errorf("token verification failed (RSAPKCS)")
	}
	return nil
}

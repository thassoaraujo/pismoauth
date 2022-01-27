package pismoauth

import (
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type TestData struct {
	HeaderName         string        `yaml:"HeaderName"`
	PismoPublicKeysURL string        `yaml:"PismoPublicKeysURL"`
	MaxAgeTime         time.Duration `yaml:"MaxAgeTime"`
}

type Enviroment struct {
	DisplayName string   `yaml:"displayName"`
	Type        string   `yaml:"type"`
	Import      string   `yaml:"import"`
	Summary     string   `yaml:"summary"`
	TestData    TestData `yaml:"testData"`
}

var data Enviroment = Enviroment{}

func TestEnviromentVariables(t *testing.T) {
	buffer, err := ioutil.ReadFile(".traefik.yml")
	if err != nil {
		t.Errorf("error: %v", err)
	}

	err = yaml.Unmarshal(buffer, &data)
	if err != nil {
		t.Errorf("error: %v", err)
	}

	if len(data.TestData.HeaderName) == 0 {
		t.Errorf("HeaderName não pode ser vazio. Informe o valor no atributo testData do arquivo .traefik.yml!")
	}
	if len(data.TestData.PismoPublicKeysURL) == 0 {
		t.Errorf("PismoPublicKeysURL não pode ser vazio. Informe o valor no atributo testData do arquivo .traefik.yml!")
	}
}

func TestFetchKeysAndCheckToken(t *testing.T) {
	buffer, err := ioutil.ReadFile(".traefik.yml")
	if err != nil {
		t.Errorf("error: %v", err)
	}

	data := Enviroment{}
	err = yaml.Unmarshal(buffer, &data)
	if err != nil {
		t.Errorf("error: %v", err)
	}

	/*
	* Criando um mock da request
	 */
	req, err := http.NewRequest("POST", "", nil)
	req.Header.Add("Authorization", "Bearer eyJraWQiOiIxM2NlZWVlYjFhMDY1NTc4OGNlMjA4NGZmZmNhZDAyZjUxZmMzMTQwIiwiYWxnIjoiUlMyNTYifQ.eyJib2R5LWhhc2giOiJQQm5lZXhGeVlcLzcyaVJiNnBcL1VSbEVCMFpPa2FnRFByRlNrc0ZiZndmaE09Iiwic3ViIjoiYXV0aG9yaXphdGlvbiIsImFjY291bnQtaWQiOjEwMjM0MTQ0MywiaXNzIjoiYXBpLnBpc21vLmlvIiwiZXhwIjoxNjM4MTQ0MDAwLCJpYXQiOjE2MzcyODAwMDAsInBhbi1oYXNoIjoiaCtQTWo5SWZYS1dzMEpWdHUrQ1BhWGF2WHhFMGxkMWlcL1BuNkM5cXNib2xFSmlwY2lhclZFbVQ1OUw5ZktMSkZJdm1ncFdMN1wvQk9pRmxYcGl6R0Uzdz09In0.BRD17fuSzIDH-137WvGwUttULel75IZFHg3UaGGTdnOdIDqWbNbOM_Cw-geLOqb4qtRfbYspEV103q4CH0QQGdXRj_n2iyltST0ahnzy4i8Xtj3GF7SYGjJAVVkef21_s1KomY3cnjzfEFtTwbLN-ycRHwFVCVGUnxq-i5DsMw0aYVeuGcVoZHDkoApWWShWHQEgDR8MzWt6xduuDYXZxbMz_9bopc14gETeo4SJ-RyTniPLHEqy5yZXRMPjDr_SvABf5e9XZ3tZ1b3kVOp8QRFq9RDjDlLiBXAbI9NFF3xTV_RGqi2G8MxRZk2Zr1U5EXZDi9XSmHmCdYY_afxteQ")

	pismoAuth := &PismoAuth{
		headerName:         data.TestData.HeaderName,
		pismoPublicKeysURL: data.TestData.PismoPublicKeysURL,
	}

	FetchKeys(pismoAuth)
	CheckToken(req, pismoAuth)
}

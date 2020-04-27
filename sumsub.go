package sumsub

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	client *http.Client
)

type API struct {
	client         *http.Client
	token          string
	tokenUpdatedAt time.Time

	apiKey         string
	login          string
	password       string
	domain         string
	appToken       string
	appTokenSecret string
}

func init() {
	client = &http.Client{}
}

func New(appToken, appTokenSecret, domain string) *API {
	return &API{
		client:         &http.Client{},
		token:          "",
		tokenUpdatedAt: time.Time{},
		domain:         domain,
		appToken:       appToken,
		appTokenSecret: appTokenSecret,
	}
}

func (api *API) TokenSet(token string) {
	api.token = token
	api.tokenUpdatedAt = time.Now()
}

func (api *API) AccessTokenGet(accountId string) (string, error) {
	var (
		err        error
		req        *http.Request
		jsonBody   []byte
		resp       *http.Response
		respFormat struct {
			Token     string `json:"token"`
			AccountId string `json:"userId"`
		}
		t    = time.Now().Unix()
		body string
	)

	body = `userId=` + accountId
	if req, err = http.NewRequest("POST", api.domain+"/resources/accessTokens?"+body, nil); err != nil {
		return "", err
	}
	req.Header.Add("Accept", "application/json")

	req.Header.Add("X-App-Token", api.appToken)
	req.Header.Add("X-App-Access-Ts", strconv.FormatInt(t, 10))
	req.Header.Add("X-App-Access-Sig", signature(t, api.appTokenSecret, "POST", "/resources/accessTokens?"+body, ""))

	if resp, err = client.Do(req); err != nil {
		return "", err
	}
	defer resp.Body.Close()
	jsonBody, _ = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("[accessToken] status code = %d, body %s", resp.StatusCode, string(jsonBody))
	}

	if err = json.Unmarshal(jsonBody, &respFormat); err != nil {
		return "", err
	}

	return respFormat.Token, nil
}

func (api *API) ApplicantCreate(accountId string) (applicantId string, err error) {
	var (
		request *http.Request
		//token   string
		body = `{
			"externalUserId": "${user_id}",
			"requiredIdDocs": {
				"docSets": [{
						"idDocSetType": "IDENTITY",
						"types": ["PASSPORT","ID_CARD","DRIVERS"]
					},
					{
						"idDocSetType": "SELFIE",
						"types": ["SELFIE"]
					}
				]
			}
		}`
		respFormat struct {
			Id string `json:"id"`
			//
		}
		response *http.Response
		t        = time.Now().Unix()
	)

	body = strings.Replace(body, `${user_id}`, accountId, -1)

	if request, err = http.NewRequest("POST", api.domain+`/resources/applicants`, bytes.NewBuffer([]byte(body))); err != nil {
		return "", err
	}
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	request.Header.Add("X-App-Token", api.appToken)
	request.Header.Add("X-App-Access-Ts", strconv.FormatInt(t, 10))
	request.Header.Add("X-App-Access-Sig", signature(t, api.appTokenSecret, "POST", "/resources/applicants", body))

	if response, err = client.Do(request); err != nil {
		return "", err
	}
	defer response.Body.Close()
	jsonBody, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode == 200 || response.StatusCode == 201 {
		if err = json.Unmarshal(jsonBody, &respFormat); err != nil {
			return "", err
		}
		return respFormat.Id, nil
	} else if response.StatusCode == 409 {
		if respFormat.Id, err = api.ApplicantIdGet(accountId); err != nil {
			return "", fmt.Errorf("error when getting applicant id = %s, status: %s body: %s", accountId, response.Status, string(jsonBody))
		}
		return respFormat.Id, nil
	} else {
		return "", fmt.Errorf("error when creating applicant id = %s, status: %s body: %s", accountId, response.Status, string(jsonBody))
	}
}

func (api *API) ApplicantIdGet(accountId string) (string, error) {
	var (
		request *http.Request
		resp    struct {
			List struct {
				Items []struct {
					Id string `json:"id"`
					//
				} `json:"items"`
			} `json:"list"`
			Id string `json:"id"`
		}
		response *http.Response
		err      error
		t        = time.Now().Unix()
	)

	if request, err = http.NewRequest("GET", api.domain+`/resources/applicants/-;externalUserId=`+accountId, nil); err != nil {
		return "", err
	}
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	request.Header.Add("X-App-Token", api.appToken)
	request.Header.Add("X-App-Access-Ts", strconv.FormatInt(t, 10))
	request.Header.Add("X-App-Access-Sig", signature(t, api.appTokenSecret, "GET", `/resources/applicants/-;externalUserId=`+accountId, ""))

	if response, err = client.Do(request); err != nil {
		return "", err
	}
	defer response.Body.Close()
	jsonBody, _ := ioutil.ReadAll(response.Body)
	if response.StatusCode == 200 {
		if err = json.Unmarshal(jsonBody, &resp); err != nil {
			return "", err
		}
		if len(resp.List.Items) > 0 {
			return resp.List.Items[0].Id, nil
		} else {
			return "", fmt.Errorf("error when getting applicant id. AccountId = %s, body %s", accountId, string(jsonBody))
		}
	} else {
		return "", fmt.Errorf("error when getting applicant id. AccountId = %s, body %s", accountId, string(jsonBody))
	}
}

func (api *API) AuthTokenGet() (string, error) {
	var err error
	var token string
	if time.Now().Sub(api.tokenUpdatedAt) > time.Hour*24 {
		if token, err = api.authLoginPost(); err != nil {
			return "", err
		} else {
			api.tokenUpdatedAt = time.Now()
			api.token = token
		}
	}

	return api.token, nil
}

func (api *API) authLoginPost() (string, error) {
	var (
		request    *http.Request
		err        error
		token      string
		respFormat struct {
			Status string `json:"status"`
			Token  string `json:"payload"`
		}
		jsonBody []byte
		resp     *http.Response
	)

	if request, err = http.NewRequest("POST", api.domain+`/resources/auth/login`, nil); err != nil {
		return "", err
	}

	token = "Basic " + base64.StdEncoding.EncodeToString([]byte(api.login+":"+api.password))

	request.Header.Add("Authorization", token)
	if resp, err = client.Do(request); err != nil {
		return "", err
	}

	defer resp.Body.Close()
	jsonBody, _ = ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status code = %d, body %s", resp.StatusCode, string(jsonBody))
	}

	if err = json.Unmarshal(jsonBody, &respFormat); err != nil {
		return "", err
	}

	return respFormat.Token, nil
}

func signature(time int64, key, method, uri, body string) string {
	dataToSign := strconv.FormatInt(time, 10) + method + uri + string(body)
	sig := hmac.New(sha256.New, []byte(key))
	sig.Write([]byte(dataToSign))
	return hex.EncodeToString(sig.Sum(nil))
}

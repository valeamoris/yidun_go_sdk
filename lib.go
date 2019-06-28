package yidun_go_sdk

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func genSignature(secretKey string, params map[string]string) string {
	var keys []string
	for key, _ := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	buf := bytes.NewBufferString("")
	for _, key := range keys {
		buf.WriteString(key + params[key])
	}
	buf.WriteString(secretKey)
	has := md5.Sum(buf.Bytes())
	return fmt.Sprintf("%x", has)
}

const VerifyUrl = "http://c.dun.163yun.com/api/v2/verify"

type YiDun struct {
	captchaId string
	secretId  string
	secretKey string
}

func New(captchaId, secretId, secretKey string) *YiDun {
	return &YiDun{
		captchaId: captchaId,
		secretId:  secretId,
		secretKey: secretKey,
	}
}

type Response struct {
	Result    bool   `json:"result"`
	Error     int    `json:"error"`
	Msg       string `json:"msg"`
	ExtraData string `json:"extra_data"`
}

func (yidun *YiDun) Verify(validate string) (bool, error) {
	params := make(map[string]string)
	params["captchaId"] = yidun.captchaId
	params["validate"] = validate
	params["user"] = ""
	params["secretId"] = yidun.secretId
	params["version"] = "v2"
	unixnano := time.Now().UnixNano()
	params["timestamp"] = fmt.Sprintf("%d", unixnano/1e6)
	nonce := rand.New(rand.NewSource(unixnano)).Int31n(1000000)
	params["nonce"] = fmt.Sprintf("%d", nonce)

	sign := genSignature(yidun.secretKey, params)
	params["sign"] = sign

	data := url.Values{}
	for k, v := range params {
		data.Set(k, v)
	}

	resp, err := http.Post(VerifyUrl, "application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	response := new(Response)
	err = json.Unmarshal(result, response)
	if err != nil {
		return false, err
	}
	fmt.Printf("%#v\n", response)
	if !response.Result {
		return false, errors.New(fmt.Sprintf("Yidun request failed with error code: %d, message: %s",
			response.Error, response.Msg))
	}
	return true, nil
}

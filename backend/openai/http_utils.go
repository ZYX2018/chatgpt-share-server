package openai

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
)

func DoPost(url string, playLoad io.Reader, header map[string]string) (*ResultVO, error) {

	req, err := http.NewRequest("POST", url, playLoad)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if header != nil {
		for k, v := range header {
			req.Header.Set(k, v)
		}

	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		return nil, err
	}
	oauthResponseStr := string(body)
	log.Println("post url:", url, "arg:", playLoad, "response: ", oauthResponseStr)
	var vo ResultVO
	err = json.Unmarshal([]byte(oauthResponseStr), &vo)
	if err != nil {
		return nil, errors.New(oauthResponseStr)
	}
	return &vo, nil
}

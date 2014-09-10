package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

func dnsRegCall(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	strbody := string(body)
	if strbody != "ok" {
		return errors.New(strbody)
	}
	return nil
}

func dnsRegisterDomain(domain, dstIP string) error {
	var ret error
	for _, server := range config.dnsAPIServers {
		url := fmt.Sprintf("http://%s/set/host/%s/%s/%s/", server, config.httpApiKey, domain, dstIP)
		err := dnsRegCall(url)
		if err != nil {
			ret = err
		}
	}
	return ret
}

func dnsUpdateDomain(domain, dstIP string) error {
	return dnsRegisterDomain(domain, dstIP)
}

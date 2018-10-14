package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"code.hackerspace.pl/q3k/mirko"
	"github.com/cenkalti/backoff"
	"github.com/golang/glog"
)

var (
	reSessionCookie = regexp.MustCompile("'SESSION_COOKIE' : '([^']*)'")
	reIpmiPriv      = regexp.MustCompile("'IPMI_PRIV' : ([^,]*)")
	reExtPriv       = regexp.MustCompile("'EXT_PRIV' : ([^,]*)")
	reSystemModel   = regexp.MustCompile("'SYSTEM_MODEL' : '([^']*)'")
	reArgument      = regexp.MustCompile("<argument>([^<]*)</argument>")
)

var (
	ErrorNoFreeSlot = fmt.Errorf("iDRAC reports no free slot")
)

type cmcRequestType int

const (
	cmcRequestKVMDetails cmcRequestType = iota
)

type cmcResponse struct {
	data interface{}
	err  error
}

type cmcRequest struct {
	t        cmcRequestType
	req      interface{}
	res      chan cmcResponse
	canceled bool
}

type KVMDetails struct {
	arguments []string
}

type cmcClient struct {
	session string
	req     chan *cmcRequest
}

func (c *cmcClient) RequestKVMDetails(ctx context.Context, slot int) (*KVMDetails, error) {
	r := &cmcRequest{
		t:   cmcRequestKVMDetails,
		req: slot,
		res: make(chan cmcResponse, 1),
	}
	mirko.Trace(ctx, "cmcRequestKVMDetails: requesting...")
	c.req <- r
	mirko.Trace(ctx, "cmcRequestKVMDetails: requested.")

	select {
	case <-ctx.Done():
		r.canceled = true
		return nil, context.Canceled
	case res := <-r.res:
		mirko.Trace(ctx, "cmcRequestKVMDetails: got response")
		if res.err != nil {
			return nil, res.err
		}
		return res.data.(*KVMDetails), nil
	}
}

func NewCMCClient() *cmcClient {
	return &cmcClient{
		req: make(chan *cmcRequest, 4),
	}
}

func (c *cmcClient) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			c.logout()
			return
		case msg := <-c.req:
			c.handle(msg)
		}
	}
}

func (c *cmcClient) handle(r *cmcRequest) {
	switch {
	case r.t == cmcRequestKVMDetails:
		var details *KVMDetails
		slot := r.req.(int)
		err := backoff.Retry(func() error {
			if err := c.login(); err != nil {
				return err
			}
			url, err := c.getiDRACURL(slot)
			if err != nil {
				return err
			}
			details, err = c.getiDRACJNLP(url)
			return err
		}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 2))

		if err != nil {
			r.res <- cmcResponse{err: err}
		}

		r.res <- cmcResponse{data: details}
	default:
		panic("invalid cmcRequestType")
	}
}

func makeUrl(path string) string {
	if strings.HasSuffix(flagCMCAddress, "/") {
		return flagCMCAddress + path
	}
	return flagCMCAddress + "/" + path
}

func (c *cmcClient) transport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

func (c *cmcClient) addCookies(req *http.Request) {
	req.AddCookie(&http.Cookie{Name: "custom_domain", Value: ""})
	req.AddCookie(&http.Cookie{Name: "domain_selected", Value: "This Chassis"})
	if c.session != "" {
		glog.Infof("Adding session: %v", c.session)
		req.AddCookie(&http.Cookie{Name: "sid", Value: c.session})
	}
}

func (c *cmcClient) getiDRACURL(slot int) (string, error) {
	if c.session == "" {
		return "", fmt.Errorf("not logged in")
	}

	url := makeUrl(pathiDRACURL) + fmt.Sprintf("?vKVM=1&serverSlot=%d", slot)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("GET prepare to %s failed: %v", pathLogin, err)
	}
	c.addCookies(req)

	cl := &http.Client{
		Transport: c.transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := cl.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET to %s failed: %v", pathLogin, err)
	}

	if resp.StatusCode != 302 {
		return "", fmt.Errorf("expected 302 on iDRAC URL redirect, got %v instead", resp.Status)
	}

	loc, _ := resp.Location()

	if !strings.Contains(loc.String(), "cmc_sess_id") {
		c.session = ""
		return "", fmt.Errorf("redirect URL contains no session ID - session timed out?")
	}

	return loc.String(), nil
}

func (c *cmcClient) getiDRACJNLP(loginUrl string) (*KVMDetails, error) {
	lurl, err := url.Parse(loginUrl)
	if err != nil {
		return nil, err
	}

	sessid := lurl.Query().Get("cmc_sess_id")
	if sessid == "" {
		return nil, fmt.Errorf("no cmc_sess_id in iDRAC login URL")
	}

	createURL := *lurl
	createURL.Path = "/Applications/dellUI/RPC/WEBSES/create.asp"
	createURL.RawQuery = ""

	values := url.Values{}
	values.Set("WEBVAR_USERNAME", "cmc")
	values.Set("WEBVAR_PASSWORD", sessid)
	values.Set("WEBVAR_ISCMCLOGIN", "1")
	valuesString := values.Encode()
	req, err := http.NewRequest("POST", createURL.String(), strings.NewReader(valuesString))

	cl := &http.Client{
		Transport: c.transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	first := func(v [][]byte) string {
		if len(v) < 1 {
			return ""
		}
		return string(v[1])
	}

	sessionCookie := first(reSessionCookie.FindSubmatch(data))
	ipmiPriv := first(reIpmiPriv.FindSubmatch(data))
	extPriv := first(reExtPriv.FindSubmatch(data))
	systemModel := first(reSystemModel.FindSubmatch(data))

	if sessionCookie == "Failure_No_Free_Slot" {
		return nil, ErrorNoFreeSlot
	}

	jnlpURL := *lurl
	jnlpURL.Path = "/Applications/dellUI/Java/jviewer.jnlp"
	jnlpURL.RawQuery = ""

	req, err = http.NewRequest("GET", jnlpURL.String(), nil)
	for _, cookie := range resp.Cookies() {
		glog.Infof("%+v", cookie)
		req.AddCookie(cookie)
	}
	req.AddCookie(&http.Cookie{Name: "SessionCookie", Value: sessionCookie})
	req.AddCookie(&http.Cookie{Name: "SessionCookieUser", Value: "cmc"})
	req.AddCookie(&http.Cookie{Name: "IPMIPriv", Value: ipmiPriv})
	req.AddCookie(&http.Cookie{Name: "ExtPriv", Value: extPriv})
	req.AddCookie(&http.Cookie{Name: "SystemModel", Value: systemModel})

	resp, err = cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// yes we do parse xml with regex why are you asking
	matches := reArgument.FindAllSubmatch(data, -1)

	res := &KVMDetails{
		arguments: []string{},
	}
	for _, match := range matches {
		res.arguments = append(res.arguments, string(match[1]))
	}

	return res, nil
}

func (c *cmcClient) login() error {
	if c.session != "" {
		return nil
	}

	values := url.Values{}
	values.Set("ST2", "NOTSET")
	values.Set("user", flagCMCUsername)
	values.Set("user_id", flagCMCUsername)
	values.Set("password", flagCMCPassword)
	values.Set("WEBSERVER_timeout", "1800")
	values.Set("WEBSERVER_timeout_select", "1800")
	valuesString := values.Encode()
	glog.Info(valuesString)
	req, err := http.NewRequest("POST", makeUrl(pathLogin), strings.NewReader(valuesString))
	if err != nil {
		return fmt.Errorf("POST prepare to %s failed: %v", pathLogin, err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	c.addCookies(req)

	cl := &http.Client{
		Transport: c.transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("POST to %s failed: %v", pathLogin, err)
	}
	glog.Infof("Login response: %s", resp.Status)
	defer resp.Body.Close()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "sid" {
			c.session = cookie.Value
			break
		}
	}
	if c.session == "" {
		return fmt.Errorf("login unsuccesful")
	}
	return nil
}

func (c *cmcClient) logout() {
	glog.Infof("Killing session..")
	if c.session == "" {
		return
	}

	req, err := http.NewRequest("GET", makeUrl(pathLogout), nil)
	if err != nil {
		glog.Errorf("GET prepare to %s failed: %v", pathLogin, err)
	}
	c.addCookies(req)

	cl := &http.Client{
		Transport: c.transport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := cl.Do(req)
	if err != nil {
		glog.Errorf("GET to %s failed: %v", pathLogin, err)
	}
	glog.Infof("Logout response: %s", resp.Status)
	return
}

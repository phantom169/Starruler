package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	Register(&HTTPBasicAuth{})
	Register(&HTTPFormAuth{})
	Register(&TomcatAuth{})
}

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // 不跟随跳转，按状态码判定
	},
}

func buildURL(a Attempt, defScheme string, defPort int, path string) string {
	u := a.Params["url"]
	if u == "" {
		scheme := defScheme
		if s := a.Params["scheme"]; s != "" {
			scheme = s
		}
		u = fmt.Sprintf("%s://%s:%d%s", scheme, a.IP, normalizePort(a.Port, defPort), path)
	}
	return u
}

// ---------- HTTP Basic ----------

type HTTPBasicAuth struct{}

func (x *HTTPBasicAuth) Protocol() string { return "http_basic" }
func (x *HTTPBasicAuth) DefaultPort() int { return 80 }

func (x *HTTPBasicAuth) Try(a Attempt) Result {
	u := buildURL(a, "http", x.DefaultPort(), "/")
	req, _ := http.NewRequest("GET", u, nil)
	req.SetBasicAuth(a.Username, a.Password)
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == 401:
		return Result{}
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		return Result{Hit: true, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	default:
		return Result{Manual: true, Detail: fmt.Sprintf("HTTP %d 需人工确认", resp.StatusCode)}
	}
}

// ---------- HTTP 表单（任意 Web 登录口） ----------

type HTTPFormAuth struct{}

func (x *HTTPFormAuth) Protocol() string { return "http_form" }
func (x *HTTPFormAuth) DefaultPort() int { return 80 }

func (x *HTTPFormAuth) Try(a Attempt) Result {
	u := buildURL(a, "http", x.DefaultPort(), "/login")
	userField := a.Params["user_field"]
	if userField == "" {
		userField = "username"
	}
	passField := a.Params["pass_field"]
	if passField == "" {
		passField = "password"
	}
	form := url.Values{}
	form.Set(userField, a.Username)
	form.Set(passField, a.Password)
	for k, v := range a.Params {
		if strings.HasPrefix(k, "extra_") {
			form.Set(strings.TrimPrefix(k, "extra_"), v)
		}
	}
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	sb := string(body)

	if re := a.Params["success_regex"]; re != "" {
		if ok, _ := regexp.MatchString(re, sb); ok {
			return Result{Hit: true, Detail: fmt.Sprintf("HTTP %d 命中成功特征", resp.StatusCode)}
		}
	}
	if re := a.Params["fail_regex"]; re != "" {
		if ok, _ := regexp.MatchString(re, sb); ok {
			return Result{}
		}
	}
	// 无特征可判：留人工
	return Result{Manual: true, Detail: fmt.Sprintf("HTTP %d 响应无判定特征，需配置 success_regex", resp.StatusCode)}
}

// ---------- Tomcat Manager ----------

type TomcatAuth struct{}

func (x *TomcatAuth) Protocol() string { return "tomcat" }
func (x *TomcatAuth) DefaultPort() int { return 8080 }

func (x *TomcatAuth) Try(a Attempt) Result {
	u := buildURL(a, "http", x.DefaultPort(), "/manager/html")
	req, _ := http.NewRequest("GET", u, nil)
	req.SetBasicAuth(a.Username, a.Password)
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{Detail: "网络错误: " + truncate(err.Error())}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == 401:
		return Result{}
	case resp.StatusCode == 200:
		return Result{Hit: true, Detail: "Tomcat Manager 登录成功"}
	default:
		return Result{Manual: true, Detail: fmt.Sprintf("HTTP %d（Manager 可能未部署）", resp.StatusCode)}
	}
}

package common

import (
	"fmt"
	"net/url"
	"strings"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type URL struct {
	Name     string
	URL      string
	User     string
	Password string
}

func ParseURL(s string, defSchema string) (*url.URL, error) {

	schema := defSchema
	rest := s

	arr := strings.Split(s, "://")

	if len(arr) == 2 {
		s1 := arr[0]
		if !utils.IsEmpty(s1) {
			schema = s1
		}
		rest = arr[1]
	}

	var up string
	var userInfo *url.Userinfo

	host := rest
	arr = strings.Split(rest, "@")
	if len(arr) > 2 {
		host = arr[len(arr)-1]
		up = strings.Join(arr[:len(arr)-1], "@")
	} else if len(arr) == 2 {
		up = arr[0]
		host = arr[1]
	}

	if !utils.IsEmpty(up) {
		var user, pass string
		uspa := strings.Split(up, ":")
		if len(uspa) == 2 {
			user = uspa[0]
			pass = uspa[1]
		} else {
			user = up
		}
		userInfo = url.UserPassword(strings.TrimSpace(user), strings.TrimSpace(pass))
	}

	u := &url.URL{
		Scheme: strings.TrimSpace(schema),
		User:   userInfo,
		Host:   strings.TrimSpace(host),
	}

	return u, nil
}

// prometheus=prometheus.service.svc:9090, victoria=https://user:pass@victoria.some.where, source2=http://prometheus.location
func ParseNames(names string, logger sreCommon.Logger) []URL {

	nameItems := RemoveEmptyStrings(strings.Split(names, ","))
	var arr []URL

	for index, item := range nameItems {

		var name, nurl string
		parts := strings.SplitN(item, "=", 2)
		if len(parts) == 2 {
			name = strings.TrimSpace(parts[0])
			nurl = strings.TrimSpace(parts[1])
		} else {
			name = fmt.Sprintf("unknown%d", index)
			nurl = strings.TrimSpace(parts[0])
		}

		u, err := ParseURL(nurl, "http")
		if err != nil {
			logger.Error(err)
			continue
		}

		user := ""
		password := ""
		if u.User != nil {
			user = u.User.Username()
			password, _ = u.User.Password()
			u.User = nil // remove user
		}

		ru := URL{
			Name:     name,
			URL:      u.String(),
			User:     user,
			Password: password,
		}

		arr = append(arr, ru)
	}
	return arr
}

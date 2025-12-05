package common

import (
	"fmt"
	"net/url"
	"strings"

	sreCommon "github.com/devopsext/sre/common"
)

type URL struct {
	Name     string
	URL      string
	User     string
	Password string
}

func ParseURL(s string, defSchema string) (*url.URL, error) {

	schema, ur, sfound := strings.Cut(s, "://")

	if !sfound {
		// If no schema is found, then ur = input
		ur = schema
		schema = defSchema

	}

	host, path, _ := strings.Cut(ur, "/")
	// Extract user credentials from input string, if such are present
	up, hostup, ufound := strings.Cut(host, "@")

	var userInfo *url.Userinfo

	if ufound {
		// if user-pass was present in input string, then 'ur' value will still have it, hence we need result of the second cut
		host = hostup
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
		Path:   path,
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

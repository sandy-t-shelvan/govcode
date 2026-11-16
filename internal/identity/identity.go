// Package identity reports who is running govcode. Identity comes from the
// kernel (real uid), never from $USER/$LOGNAME, which the caller controls.
package identity

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

type User struct {
	UID      int    `json:"uid"`
	Username string `json:"username"`
	Host     string `json:"host"`
}

func (u User) String() string { return fmt.Sprintf("%s(uid=%d)@%s", u.Username, u.UID, u.Host) }

func Current() (User, error) {
	uid := os.Getuid()
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return User{}, fmt.Errorf("identity: cannot resolve uid %d: %w", uid, err)
	}
	host, _ := os.Hostname()
	return User{UID: uid, Username: u.Username, Host: host}, nil
}

// Lookup resolves a username to its uid.
func Lookup(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(u.Uid)
}

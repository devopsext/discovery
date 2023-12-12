package common

type Discovery interface {
	Discover()
	Name() string
	Source() string
}

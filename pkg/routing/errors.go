package routing

import "errors"

var (
	ErrRouteNotFound      = errors.New("route not found")
	ErrInvalidRoute       = errors.New("invalid route")
	ErrInvalidPathPattern = errors.New("invalid path pattern")
	ErrInvalidTemplate    = errors.New("invalid resource id template")
)

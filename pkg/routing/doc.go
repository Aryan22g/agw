// Package routing maps an HTTP request to the action, resource and risk class
// that policy is written in terms of.
//
// A Registry holds routes (method and path pattern to action, resource
// template and risk class) and answers which route a request matches, so that
// authorization reasons about "github.issue.create on acme/app" rather than
// about URLs.
//
// This is a public package of github.com/Aryan22g/agw, at v0: a breaking
// change is possible between minor releases and is listed in CHANGELOG.md.
package routing

package gost

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNodeDefaultWhitelist(t *testing.T) {
	assert := assert.New(t)

	node, _ := ParseProxyNode("http2://localhost:8000")

	assert.True(node.Can("connect", "google.pl:80"))
	assert.True(node.Can("connect", "google.pl:443"))
	assert.True(node.Can("connect", "google.pl:22"))
	assert.True(node.Can("bind", "google.pl:80"))
	assert.True(node.Can("bind", "google.com:80"))
}

func TestNodeWhitelist(t *testing.T) {
	assert := assert.New(t)

	node, _ := ParseProxyNode("http2://localhost:8000?whitelist=connect:google.pl:80,443")

	assert.True(node.Can("connect", "google.pl:80"))
	assert.True(node.Can("connect", "google.pl:443"))
	assert.False(node.Can("connect", "google.pl:22"))
	assert.False(node.Can("bind", "google.pl:80"))
	assert.False(node.Can("bind", "google.com:80"))
}

func TestNodeBlacklist(t *testing.T) {
	assert := assert.New(t)

	node, _ := ParseProxyNode("http2://localhost:8000?blacklist=connect:google.pl:80,443")

	assert.False(node.Can("connect", "google.pl:80"))
	assert.False(node.Can("connect", "google.pl:443"))
	assert.True(node.Can("connect", "google.pl:22"))
	assert.True(node.Can("bind", "google.pl:80"))
	assert.True(node.Can("bind", "google.com:80"))
}

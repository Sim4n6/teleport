/*

 Copyright 2022 Gravitational, Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

*/

package redis

import (
	"net"
	"net/url"
	"strings"

	"github.com/gravitational/trace"
)

// DefaultPort is the Redis default port.
const DefaultPort = "6379"

const (
	URIScheme    = "redis"
	URISchemeSSL = "rediss"
)

// ConnectionMode defines the mode in which Redis is configured. Currently, supported are single and cluster.
type ConnectionMode string

const (
	// Single mode should be used when connecting to a single Redis instance.
	Single ConnectionMode = "single"
	// Cluster mode should be used then connecting to a Redis Cluster.
	Cluster ConnectionMode = "cluster"
)

// ConnectionOptions defines Redis connection options.
type ConnectionOptions struct {
	// mode defines Redis connection mode like cluster or single instance.
	mode ConnectionMode
	// address of Redis instance.
	address string
	// port on which Redis expects new connections.
	port string
}

// ParseRedisURI parses a Redis connection string and returns the parsed
// connection options like address and connection mode.
// ex: rediss://redis.example.com:6379?mode=cluster
func ParseRedisURI(uri string) (*ConnectionOptions, error) {
	if uri == "" {
		return nil, trace.BadParameter("Redis uri is empty")
	}

	u, err := url.Parse(uri)
	if err != nil {
		return nil, trace.BadParameter("failed to parse Redis URI: %v", err)
	}

	switch u.Scheme {
	case URIScheme, URISchemeSSL:
	default:
		return nil, trace.BadParameter("invalid Redis URI scheme: %q. Expected %q or %q.",
			u.Scheme, URIScheme, URISchemeSSL)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, trace.BadParameter("failed to parse Redis host: %v", err)
	}

	if port == "" {
		port = DefaultPort
	}

	values := u.Query()
	// Get additional connections options

	// Default to the single mode.
	mode := Single
	if values.Has("mode") {
		connMode := strings.ToLower(values.Get("mode"))
		switch ConnectionMode(connMode) {
		case Single:
			mode = Single
		case Cluster:
			mode = Cluster
		default:
			return nil, trace.BadParameter("incorrect connection mode %q, supported are: %s and %s",
				connMode, Single, Cluster)
		}
	}

	return &ConnectionOptions{
		mode:    mode,
		address: host,
		port:    port,
	}, nil
}

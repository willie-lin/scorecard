// Copyright 2020 Security Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package roundtripper

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/google/go-github/v32/github"
	cache "github.com/naveensrinivasan/httpcache"
	"github.com/naveensrinivasan/httpcache/diskcache"
	"github.com/peterbourgon/diskv"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	GithubAuthToken         = "GITHUB_AUTH_TOKEN" // #nosec G101
	GithubAppKeyPath        = "GITHUB_APP_KEY_PATH"
	GithubAppID             = "GITHUB_APP_ID"
	GithubAppInstallationID = "GITHUB_APP_INSTALLATION_ID"
	UseDiskCache            = "USE_DISK_CACHE"
	DiskCachePath           = "DISK_CACHE_PATH"
	UseBlobCache            = "USE_BLOB_CACHE"
	BucketURL               = "BLOB_URL"
	writeDelay              = 1 * time.Second
)

type RoundRobinTokenSource struct {
	counter      int64
	AccessTokens []string
}

func (r *RoundRobinTokenSource) Token() (*oauth2.Token, error) {
	c := atomic.AddInt64(&r.counter, 1)
	index := c % int64(len(r.AccessTokens))
	return &oauth2.Token{
		AccessToken: r.AccessTokens[index],
	}, nil
}

// NewTransport returns a configured http.Transport for use with GitHub.
func NewTransport(ctx context.Context, logger *zap.SugaredLogger) http.RoundTripper {
	// Start with oauth
	transport := http.DefaultTransport
	if token := os.Getenv(GithubAuthToken); token != "" {
		ts := &RoundRobinTokenSource{
			AccessTokens: strings.Split(token, ","),
		}
		transport = oauth2.NewClient(ctx, ts).Transport
	} else if keyPath := os.Getenv(GithubAppKeyPath); keyPath != "" { // Also try a GITHUB_APP
		appID, err := strconv.Atoi(os.Getenv(GithubAppID))
		if err != nil {
			log.Panic(err)
		}
		installationID, err := strconv.Atoi(os.Getenv(GithubAppInstallationID))
		if err != nil {
			log.Panic(err)
		}
		transport, err = ghinstallation.NewKeyFromFile(transport, int64(appID), int64(installationID), keyPath)
		if err != nil {
			log.Panic(err)
		}
	}

	rateLimit := &RateLimitTransport{transport: transport, Logger: logger}

	// uses blob cache like GCS,S3.
	if cachePath, useBlob := shouldUseBlobCache(); useBlob {
		b, e := New(context.Background(), cachePath)
		if e != nil {
			log.Panic(e)
		}

		c := cache.NewTransport(b)
		c.Transport = rateLimit
		return c
	}

	// uses the disk cache
	if cachePath, useDisk := shouldUseDiskCache(); useDisk {
		const cacheSize uint64 = 10000 * 1024 * 1024 // 10gb
		c := cache.NewTransport(diskcache.NewWithDiskv(
			diskv.New(diskv.Options{BasePath: cachePath, CacheSizeMax: cacheSize})))
		c.Transport = rateLimit
		return c
	}

	// uses memory cache
	c := cache.NewTransport(cache.NewMemoryCache())
	c.Transport = rateLimit
	return c
}

// shouldUseDiskCache checks the env variables USE_DISK_CACHE and DISK_CACHE_PATH to determine if
// disk should be used for caching.
func shouldUseDiskCache() (string, bool) {
	if isDiskCache := os.Getenv(UseDiskCache); isDiskCache != "" {
		if result, err := strconv.ParseBool(isDiskCache); err == nil && result {
			if cachePath := os.Getenv(DiskCachePath); cachePath != "" {
				return cachePath, true
			}
		}
	}
	return "", false
}

// shouldUseBlobCache checks the env variables USE_BLOB_CACHE and BLOB_URL to determine if
// blob should be used for caching.
func shouldUseBlobCache() (string, bool) {
	if result, err := strconv.ParseBool(os.Getenv(UseBlobCache)); err == nil && result {
		if cachePath := os.Getenv(BucketURL); cachePath != "" {
			return cachePath, true
		}
	}
	return "", false
}

// RateLimitTransport implements GitHub's best practices
// for avoiding rate limits
// https://developer.github.com/v3/guides/best-practices-for-integrators/#dealing-with-abuse-rate-limits
type RateLimitTransport struct {
	Logger           *zap.SugaredLogger
	transport        http.RoundTripper
	delayNextRequest bool
}

func (rlt *RateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Make requests for a single user or client ID serially
	// This is also necessary for safely saving
	// and restoring bodies between retries below
	rlt.lock(req)

	// If you're making a large number of POST, PATCH, PUT, or DELETE requests
	// for a single user or client ID, wait at least one second between each request.
	/*
		if rlt.delayNextRequest {
			if rlt.Logger != nil {
				rlt.Logger.Warnf("[DEBUG] Sleeping %s between write operations", writeDelay)
			}
			time.Sleep(writeDelay)
		}

		rlt.delayNextRequest = isWriteMethod(req.Method)
	*/

	resp, err := rlt.transport.RoundTrip(req)
	if err != nil {
		rlt.unlock(req)
		return resp, errors.Wrap(err, "error in http roundtrip for response")
	}

	// Make response body accessible for retries & debugging
	// (work around bug in GitHub SDK)
	// See https://github.com/google/go-github/pull/986
	r1, r2, err := drainBody(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = r1
	ghErr := github.CheckResponse(resp)
	resp.Body = r2

	// When you have been limited, use the Retry-After response header to slow down.
	if arlErr, ok := ghErr.(*github.AbuseRateLimitError); ok {
		rlt.delayNextRequest = false
		retryAfter := arlErr.GetRetryAfter()
		if rlt.Logger != nil {
			rlt.Logger.Warnf("Abuse detection mechanism triggered, sleeping for %s before retrying", retryAfter)
		}
		time.Sleep(retryAfter)
		rlt.unlock(req)
		return rlt.RoundTrip(req)
	}

	if rlErr, ok := ghErr.(*github.RateLimitError); ok {
		rlt.delayNextRequest = false
		retryAfter := time.Until(rlErr.Rate.Reset.Time)
		if rlt.Logger != nil {
			rlt.Logger.Warnf("[DEBUG] Rate limit %d reached, sleeping for %s (until %s) before retrying",
				rlErr.Rate.Limit, retryAfter, time.Now().Add(retryAfter))
		}
		time.Sleep(retryAfter)
		rlt.unlock(req)
		return rlt.RoundTrip(req)
	}

	rlt.unlock(req)

	return resp, nil
}

func (rlt *RateLimitTransport) lock(req *http.Request) {
	ctx := req.Context()
	if rlt.Logger != nil {
		rlt.Logger.Debugf("[TRACE] Acquiring lock for GitHub API request (%q)", ctx)
	}
}

func (rlt *RateLimitTransport) unlock(req *http.Request) {
	ctx := req.Context()
	if rlt.Logger != nil {
		rlt.Logger.Debugf("[TRACE] Releasing lock for GitHub API request (%q)", ctx)
	}
}

func NewRateLimitTransport(rt http.RoundTripper) *RateLimitTransport {
	return &RateLimitTransport{transport: rt}
}

// drainBody reads all of b to memory and then returns two equivalent
// ReadClosers yielding the same bytes.
func drainBody(b io.ReadCloser) (r1, r2 io.ReadCloser, err error) {
	if b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return http.NoBody, http.NoBody, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, b, errors.Wrap(err, "unable to read from buffer")
	}
	if err := b.Close(); err != nil {
		return nil, b, errors.Wrap(err, "error while closing the buffer")
	}
	return ioutil.NopCloser(&buf), ioutil.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

func isWriteMethod(method string) bool {
	switch method {
	case "POST", "PATCH", "PUT", "DELETE":
		return true
	}
	return false
}

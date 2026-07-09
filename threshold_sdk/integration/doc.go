// Package thresholdsdkintegration holds the Docker-based integration test for the
// thresholdsdk leader/follower DKG and the small env-driven harness (cmd/dkgnode)
// it runs in containers. The leader/follower model needs no shared committee
// descriptor: the leader starts solo and followers join dynamically, pinning the
// leader's host key out of band, so configuration is per-role environment variables.
package thresholdsdkintegration

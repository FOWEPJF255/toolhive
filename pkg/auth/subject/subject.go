// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package subject maps the identity claims of a delegated token to the local
// user the token acts for.
package subject

import (
	"context"
	"errors"
)

// Ref is a lookup key for a subject: one claim, with its value, from one issuer.
type Ref struct {
	// Issuer is the issuer that signed the token carrying the claim.
	Issuer string
	// Claim is the name of the claim, such as "sub".
	Claim string
	// Value is the claim's value.
	Value string
}

//go:generate mockgen -destination=mocks/mock_resolver.go -package=mocks -source=subject.go Resolver

// Resolver maps a Ref to the canonical local user ID.
//
// A nil error always comes with a non-empty user ID. Resolvers never create
// users; a Ref with no local user returns ErrUnknown. Callers log the errors
// an implementation returns, so they must not include the Ref's values.
type Resolver interface {
	Resolve(ctx context.Context, ref Ref) (string, error)
}

var (
	// ErrUnknown means no local user matches the Ref. Callers refuse the token.
	ErrUnknown = errors.New("unknown subject")
	// ErrAmbiguous means more than one local user matches the Ref. Callers
	// refuse the token. Directory-backed resolvers return it; the standalone
	// resolver never does.
	ErrAmbiguous = errors.New("ambiguous subject")
	// ErrUnavailable means the resolver could not answer. Callers report a
	// server error, not invalid_grant, so the client may retry.
	ErrUnavailable = errors.New("subject resolver unavailable")
)

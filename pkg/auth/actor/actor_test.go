// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package actor

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	celcore "github.com/stacklok/toolhive-core/cel"
)

func TestEffective(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		source string
		claims map[string]any
		client string
		want   *Actor
		// wantClaims, when set, is the exact Claims the actor must carry.
		wantClaims map[string]any
		wantErr    error
		// wantFail is for errors that carry no sentinel.
		wantFail bool
		noIssuer bool
	}{
		{
			name: "outermost act wins over a nested one",
			claims: map[string]any{"act": map[string]any{
				"iss": "https://platform", "sub": "agent-1",
				"act": map[string]any{"iss": "https://other", "sub": "agent-0"},
			}},
			want:       &Actor{Source: SourceAct, Issuer: "https://platform", Subject: "agent-1"},
			wantClaims: map[string]any{"iss": "https://platform", "sub": "agent-1"},
		},
		{
			name:   "act without iss takes the token issuer",
			claims: map[string]any{"act": map[string]any{"sub": "agent-1"}},
			want:   &Actor{Source: SourceAct, Issuer: "https://token-iss", Subject: "agent-1"},
		},
		{
			name:   "explicit act source",
			source: SourceAct,
			claims: map[string]any{"act": map[string]any{"iss": "https://platform", "sub": "agent-1"}},
			want:   &Actor{Source: SourceAct, Issuer: "https://platform", Subject: "agent-1"},
		},
		{name: "act that is nil", claims: map[string]any{"act": nil}, wantErr: ErrNoActor},
		{
			name:    "act.iss that is empty",
			claims:  map[string]any{"act": map[string]any{"iss": "", "sub": "agent-1"}},
			wantErr: ErrMalformedActor,
		},
		{
			name:     "client source without a token issuer",
			source:   SourceClient,
			client:   "client-1",
			noIssuer: true,
			wantErr:  ErrMalformedActor,
		},
		{name: "no act is refused", claims: map[string]any{"sub": "u"}, wantErr: ErrNoActor},
		{name: "act that is not an object", claims: map[string]any{"act": "agent-1"}, wantErr: ErrMalformedActor},
		{name: "act without sub", claims: map[string]any{"act": map[string]any{"iss": "https://platform"}}, wantErr: ErrMalformedActor},
		{
			name:   "client source ignores act and names the client",
			source: SourceClient,
			claims: map[string]any{"act": map[string]any{"sub": "agent-1"}},
			client: "client-1",
			want:   &Actor{Source: SourceClient, Issuer: "https://token-iss", Subject: "client-1"},
		},
		{name: "client source without a client ID", source: SourceClient, wantErr: ErrMalformedActor},
		{name: "unknown source", source: "bogus", wantFail: true},
		{
			name:    "act.iss that is not a string",
			claims:  map[string]any{"act": map[string]any{"iss": 42, "sub": "agent-1"}},
			wantErr: ErrMalformedActor,
		},
		{
			name:     "no iss in act or on the token",
			claims:   map[string]any{"act": map[string]any{"sub": "agent-1"}},
			noIssuer: true,
			wantErr:  ErrMalformedActor,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tokenIssuer := "https://token-iss"
			if tt.noIssuer {
				tokenIssuer = ""
			}
			got, err := Effective(tt.source, tt.claims, tokenIssuer, tt.client)
			if tt.wantErr != nil || tt.wantFail {
				require.Error(t, err)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Source, got.Source)
			assert.Equal(t, tt.want.Issuer, got.Issuer)
			assert.Equal(t, tt.want.Subject, got.Subject)
			if tt.wantClaims != nil {
				assert.Equal(t, tt.wantClaims, got.Claims)
			}
			if tt.want.Source == SourceAct {
				assert.NotContains(t, got.Claims, "act")
			}
		})
	}
}

func TestNewDefaultPolicy_Refusals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		issuers  []string
		subjects []string
	}{
		{name: "no issuers"},
		{name: "empty issuer", issuers: []string{""}},
		{name: "issuer with #", issuers: []string{"https://platform#frag"}},
		{name: "empty subject", issuers: []string{"https://platform"}, subjects: []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewDefaultPolicy(tt.issuers, tt.subjects, "")
			require.Error(t, err)
			assert.Nil(t, p)
		})
	}
}

func TestEffective_ClaimsDoNotAliasInput(t *testing.T) {
	t.Parallel()
	nested := map[string]any{"sub": "agent-0"}
	inner := map[string]any{"level": "high"}
	list := []any{"a", map[string]any{"k": "v"}}
	act := map[string]any{"iss": "https://platform", "sub": "agent-1", "act": nested, "meta": inner, "roles": list}
	claims := map[string]any{"act": act}

	got, err := Effective(SourceAct, claims, "https://token-iss", "")
	require.NoError(t, err)
	want := map[string]any{"iss": "https://platform", "sub": "agent-1", "meta": map[string]any{"level": "high"},
		"roles": []any{"a", map[string]any{"k": "v"}}}
	require.Equal(t, want, got.Claims)

	inner["level"] = "tampered"
	list[0] = "tampered"
	list[1].(map[string]any)["k"] = "tampered"

	assert.Equal(t, want, got.Claims)

	got.Claims["sub"] = "tampered"
	got.Claims["extra"] = true
	assert.Equal(t, "agent-1", act["sub"])
	assert.NotContains(t, act, "extra")
}

func TestDefaultPolicy_Evaluate(t *testing.T) {
	t.Parallel()
	const platform = "https://platform"
	tests := []struct {
		name       string
		subjects   []string
		actor      *Actor
		wantAllow  bool
		wantReason string
		wantPrinc  string
	}{
		{
			name:       "issuer allowed, no subject allowlist",
			actor:      &Actor{Issuer: platform, Subject: "agent-1"},
			wantAllow:  true,
			wantReason: ReasonAllowed,
			wantPrinc:  platform + "#agent-1",
		},
		{
			name:       "issuer not allowed",
			actor:      &Actor{Issuer: "https://evil", Subject: "agent-1"},
			wantReason: ReasonIssuerNotAllowed,
		},
		{
			name:       "subject on the allowlist",
			subjects:   []string{"agent-1"},
			actor:      &Actor{Issuer: platform, Subject: "agent-1"},
			wantAllow:  true,
			wantReason: ReasonAllowed,
			wantPrinc:  platform + "#agent-1",
		},
		{
			name:       "subject not on the allowlist",
			subjects:   []string{"agent-1"},
			actor:      &Actor{Issuer: platform, Subject: "agent-2"},
			wantReason: ReasonSubjectNotAllowed,
		},
		{name: "no actor", wantReason: ReasonNoActor},
		{name: "actor without subject", actor: &Actor{Issuer: platform}, wantReason: ReasonNoActor},
		{name: "actor without issuer", actor: &Actor{Subject: "agent-1"}, wantReason: ReasonNoActor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewDefaultPolicy([]string{platform}, tt.subjects, "")
			require.NoError(t, err)
			got, err := p.Evaluate(context.Background(), Request{Actor: tt.actor})
			require.NoError(t, err)
			assert.Equal(t, Decision{Allow: tt.wantAllow, Reason: tt.wantReason, Principal: tt.wantPrinc}, got)
		})
	}
}

func TestDefaultPolicy_Expression(t *testing.T) {
	t.Parallel()
	const platform = "https://platform"
	items := make([]any, 2000)
	for i := range items {
		items[i] = strconv.Itoa(i)
	}
	actor := &Actor{
		Source: SourceAct, Issuer: platform, Subject: "agent-1",
		Claims: map[string]any{"tier": "gold", "items": items},
	}
	clientActor := &Actor{Source: SourceClient, Issuer: platform, Subject: "client-1"}
	nestedActor, err := Effective(SourceAct, map[string]any{"act": map[string]any{
		"iss": platform, "sub": "agent-1",
		"act": map[string]any{"iss": platform, "sub": "agent-0"},
	}}, platform, "")
	require.NoError(t, err)
	tests := []struct {
		name       string
		expr       string
		actor      *Actor
		wantNewErr bool
		wantAllow  bool
		wantReason string
		wantErr    bool
	}{
		{name: "true allows", expr: `actor.claims.tier == "gold"`, wantAllow: true, wantReason: ReasonAllowed},
		{
			name:       "client source sees empty claims",
			expr:       `actor.source == "client" && size(actor.claims) == 0`,
			actor:      clientActor,
			wantAllow:  true,
			wantReason: ReasonAllowed,
		},
		{
			name:       "prior actor is not visible by presence",
			expr:       `has(actor.claims.act)`,
			actor:      nestedActor,
			wantReason: ReasonExpressionDenied,
		},
		{
			name:       "prior actor subject cannot be read",
			expr:       `actor.claims.act.sub == "agent-0"`,
			actor:      nestedActor,
			wantReason: ReasonExpressionError,
			wantErr:    true,
		},
		{
			name:       "has guard denies when the claim is absent",
			expr:       `has(actor.claims.role) && actor.claims.role == "x"`,
			wantReason: ReasonExpressionDenied,
		},
		{name: "false denies", expr: `actor.claims.tier == "silver"`, wantReason: ReasonExpressionDenied},
		{name: "runtime error denies", expr: `actor.claims.missing == "x"`, wantReason: ReasonExpressionError, wantErr: true},
		{
			name:       "expression over the cost limit errors",
			expr:       `actor.claims.items.all(a, actor.claims.items.all(b, a == b || a != b))`,
			wantReason: ReasonExpressionError,
			wantErr:    true,
		},
		{name: "expression longer than the cap", expr: `actor.subject == "` + strings.Repeat("x", celcore.DefaultMaxExpressionLength) + `"`, wantNewErr: true},
		{name: "syntax error", expr: `actor.claims.tier ==`, wantNewErr: true},
		{name: "non-boolean", expr: `size(actor.claims)`, wantNewErr: true},
		{name: "bare dyn claim member", expr: `actor.claims.flag`, wantNewErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewDefaultPolicy([]string{platform}, nil, tt.expr)
			if tt.wantNewErr {
				require.Error(t, err)
				assert.Nil(t, p)
				return
			}
			require.NoError(t, err)
			a := actor
			if tt.actor != nil {
				a = tt.actor
			}
			got, err := p.Evaluate(context.Background(), Request{Actor: a})
			assert.Equal(t, tt.wantErr, err != nil)
			assert.Equal(t, tt.wantAllow, got.Allow)
			assert.Equal(t, tt.wantReason, got.Reason)
		})
	}
}

func TestDefaultPolicy_CancelledContextStopsEvaluation(t *testing.T) {
	t.Parallel()
	const platform = "https://platform"
	items := make([]any, 500)
	for i := range items {
		items[i] = int64(i)
	}
	req := Request{Actor: &Actor{
		Source: SourceAct, Issuer: platform, Subject: "agent-1",
		Claims: map[string]any{"items": items},
	}}
	p, err := NewDefaultPolicy([]string{platform}, nil, `actor.claims.items.all(a, a >= 0)`)
	require.NoError(t, err)

	live, err := p.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.True(t, live.Allow)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := p.Evaluate(ctx, req)
	require.Error(t, err)
	assert.Equal(t, Decision{Reason: ReasonExpressionError}, got)
}

func TestReasons(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		ReasonAllowed:           "allowed",
		ReasonNoActor:           "no_actor",
		ReasonIssuerNotAllowed:  "actor_issuer_not_allowed",
		ReasonSubjectNotAllowed: "actor_subject_not_allowed",
		ReasonExpressionDenied:  "actor_expression_denied",
		ReasonExpressionError:   "actor_expression_error",
	}
	for got, want := range tests {
		assert.Equal(t, want, got)
	}
}

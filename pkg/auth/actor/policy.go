// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package actor

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cel.dev/cel-go/cel"

	celcore "github.com/stacklok/toolhive-core/cel"
)

// Stable reasons in Decision.Reason.
const (
	ReasonAllowed           = "allowed"
	ReasonNoActor           = "no_actor"
	ReasonIssuerNotAllowed  = "actor_issuer_not_allowed"
	ReasonSubjectNotAllowed = "actor_subject_not_allowed"
	ReasonExpressionDenied  = "actor_expression_denied"
	ReasonExpressionError   = "actor_expression_error"
)

// DefaultPolicy allows an actor whose issuer is in an allowed set, whose
// subject is in the allowlist when one is configured, and for whom the CEL
// expression, when one is configured, is true.
type DefaultPolicy struct {
	issuers  map[string]struct{}
	subjects map[string]struct{}
	program  cel.Program
}

var _ Policy = (*DefaultPolicy)(nil)

// NewDefaultPolicy returns a DefaultPolicy. issuers must be non-empty. An
// empty subjects list puts no limit on the subject. Empty strings are refused.
//
// A non-empty expr is a CEL expression that must evaluate to true. It sees one
// variable, actor, a map with the string members source, issuer and subject
// and the map claims (the outermost act object without its nested act, empty
// for SourceClient).
// It is compiled once; a compile error, an expression longer than
// toolhive-core's default cap, or an expression whose static type is not bool
// is refused. Members of actor.claims are dynamically typed, so they must be
// compared explicitly (actor.claims.admin == true, not actor.claims.admin).
// Referencing a claim the token lacks is an evaluation error (ReasonExpressionError
// plus an error, not a denial), so expressions over optional claims should guard
// with has(), for example has(actor.claims.role) && actor.claims.role == "x".
// Evaluation is limited by the same default cost limit and stops when the
// context is cancelled.
func NewDefaultPolicy(issuers, subjects []string, expr string) (*DefaultPolicy, error) {
	if len(issuers) == 0 {
		return nil, errors.New("actor policy needs at least one allowed issuer")
	}
	p := &DefaultPolicy{issuers: make(map[string]struct{}, len(issuers))}
	for _, iss := range issuers {
		if iss == "" {
			return nil, errors.New("actor policy: allowed issuer is empty")
		}
		// Principal is issuer#subject. With no # in the issuer, splitting on
		// the first # always recovers both parts.
		if strings.Contains(iss, "#") {
			return nil, fmt.Errorf("actor policy: allowed issuer %q contains #", iss)
		}
		p.issuers[iss] = struct{}{}
	}
	if len(subjects) > 0 {
		p.subjects = make(map[string]struct{}, len(subjects))
		for _, sub := range subjects {
			if sub == "" {
				return nil, errors.New("actor policy: allowed subject is empty")
			}
			p.subjects[sub] = struct{}{}
		}
	}
	if expr != "" {
		prg, err := compileExpression(expr)
		if err != nil {
			return nil, err
		}
		p.program = prg
	}
	return p, nil
}

// Evaluate implements Policy. An Actor without an issuer or a subject counts as
// no actor. It returns an error only when the CEL expression fails at run
// time. On error the Decision does not allow and the caller refuses the
// request.
func (p *DefaultPolicy) Evaluate(ctx context.Context, req Request) (Decision, error) {
	a := req.Actor
	if a == nil || a.Issuer == "" || a.Subject == "" {
		return Decision{Reason: ReasonNoActor}, nil
	}
	if _, ok := p.issuers[a.Issuer]; !ok {
		return Decision{Reason: ReasonIssuerNotAllowed}, nil
	}
	if p.subjects != nil {
		if _, ok := p.subjects[a.Subject]; !ok {
			return Decision{Reason: ReasonSubjectNotAllowed}, nil
		}
	}
	if p.program != nil {
		claims := a.Claims
		if claims == nil {
			claims = map[string]any{}
		}
		out, _, err := p.program.ContextEval(ctx, map[string]any{"actor": map[string]any{
			"source": a.Source, "issuer": a.Issuer, "subject": a.Subject, "claims": claims,
		}})
		if err != nil {
			return Decision{Reason: ReasonExpressionError}, fmt.Errorf("actor policy: evaluating expression: %w", err)
		}
		if allowed, _ := out.Value().(bool); !allowed {
			return Decision{Reason: ReasonExpressionDenied}, nil
		}
	}
	return Decision{Allow: true, Reason: ReasonAllowed, Principal: a.Issuer + "#" + a.Subject}, nil
}

func compileExpression(expr string) (cel.Program, error) {
	if len(expr) > celcore.DefaultMaxExpressionLength {
		return nil, fmt.Errorf("actor policy: expression is %d bytes, the limit is %d",
			len(expr), celcore.DefaultMaxExpressionLength)
	}
	// Built here rather than with celcore.Engine.Compile, which sets no
	// interrupt frequency, so evaluation could not stop on context cancellation.
	env, err := cel.NewEnv(cel.Variable("actor", cel.MapType(cel.StringType, cel.DynType)))
	if err != nil {
		return nil, fmt.Errorf("actor policy: creating CEL environment: %w", err)
	}
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("actor policy: compiling expression: %w", iss.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("actor policy: expression must return bool, got %s", ast.OutputType())
	}
	prg, err := env.Program(ast, cel.CostLimit(celcore.DefaultCostLimit), cel.InterruptCheckFrequency(100))
	if err != nil {
		return nil, fmt.Errorf("actor policy: building expression program: %w", err)
	}
	return prg, nil
}

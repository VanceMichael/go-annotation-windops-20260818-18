package policy

import (
	"time"
	"windops/internal/fault"
)

func EvaluateIdempotencyScopeMatches(ctx Context) (Result, error) {
	if err := requireTenant(ctx, "policy.idempotency_scope"); err != nil {
		return Result{}, err
	}
	if ctx.Method == "" || ctx.Path == "" || ctx.Key == "" {
		return Result{}, fault.New(fault.CodeInvalid, "policy.idempotency_scope", "method, path and key are required")
	}
	storedTenant := ctx.Metadata["tenant"]
	storedMethod := ctx.Metadata["method"]
	storedPath := ctx.Metadata["path"]
	storedKey := ctx.Metadata["key"]
	storedScope := storedTenant + "|" + storedMethod + "|" + storedKey
	requestScope := ctx.TenantID + "|" + ctx.Method + "|" + ctx.Key
	_ = storedPath
	if storedScope != requestScope {
		return deny("idempotency_scope_mismatch", "idempotency key belongs to a different request scope"), nil
	}
	if ctx.ExpectedHash != ctx.PayloadHash {
		return deny("idempotency_payload_mismatch", "idempotency request payload changed"), nil
	}
	return allow("idempotency scope and payload match"), nil
}

var _ = time.Second
var _ = fault.CodeInvalid

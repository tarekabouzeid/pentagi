package providers

import (
	"context"
	"sync"
	"testing"

	"pentagi/pkg/hitl"
)

func TestAssistantProvider_SetHITLGate_StampsTheAssistantOnEveryRequest(t *testing.T) {
	inner := &performerGate{res: &hitl.Resolution{Decision: hitl.DecisionApproved}}
	ap := &assistantProvider{id: 42, fp: flowProvider{mx: &sync.RWMutex{}}}
	ap.SetHITLGate(inner)

	if _, err := ap.fp.hitl().Evaluate(context.Background(), &hitl.Request{ToolName: "terminal"}); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if inner.got == nil || inner.got.AssistantID == nil || *inner.got.AssistantID != 42 {
		t.Fatalf("the gate saw %+v, want assistant 42", inner.got)
	}
}

func TestAssistantProvider_SetHITLGate_KeepsANilGateNil(t *testing.T) {
	ap := &assistantProvider{id: 42, fp: flowProvider{mx: &sync.RWMutex{}}}
	ap.SetHITLGate(nil)

	if ap.fp.hitl() != nil {
		t.Fatal("a nil gate was wrapped, so execToolCall would call into it")
	}
}

package enrichers

import (
	"testing"
)

func FuzzParsePolicyDoc(f *testing.F) {
	f.Add(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:x"}}`)
	f.Add(`{"Statement":[{"Effect":"Allow","Action":["a","b"]}]}`)
	f.Add(`[]`)
	f.Add(`"string-doc"`)
	f.Add(`{"Statement": 42}`)
	f.Fuzz(func(t *testing.T, doc string) {
		parsed := parsePolicyDoc(doc)
		if parsed != nil {
			allowedActions(parsed)
			resourcesOf(parsed)
		}
	})
}

func TestParsePolicyDocVariants(t *testing.T) {
	doc := parsePolicyDoc(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::b/*"},{"Effect":"Deny","Action":["s3:DeleteObject"],"Resource":"*"}]}`)
	if doc == nil {
		t.Fatal("parse failed")
	}
	actions := allowedActions(doc)
	if !actions["s3:GetObject"] || !actions["s3:PutObject"] {
		t.Errorf("allow actions missing: %v", actions)
	}
	if actions["s3:DeleteObject"] {
		t.Error("deny statement must not count as allowed")
	}
}

func TestParsePolicyDocGarbage(t *testing.T) {
	if parsePolicyDoc("not json {") != nil {
		t.Error("garbage JSON string must yield nil, not panic")
	}
}

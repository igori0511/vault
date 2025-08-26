// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/audit"
	credUserpass "github.com/hashicorp/vault/builtin/credential/userpass"
	"github.com/hashicorp/vault/builtin/logical/database"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/builtin/logical/transit"
	"github.com/hashicorp/vault/helper/builtinplugins"
	"github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

// testVaultServer creates a test vault cluster and returns a configured API
// client and closer function.
func testVaultServer(t testing.TB) (*api.Client, func()) {
	t.Helper()

	client, _, closer := testVaultServerUnseal(t)
	return client, closer
}

// testVaultServerUnseal creates a test vault cluster and returns a configured
// API client, list of unseal keys (as strings), and a closer function.
func testVaultServerUnseal(t testing.TB) (*api.Client, []string, func()) {
	t.Helper()

	return testVaultServerCoreConfig(t, &vault.CoreConfig{
		CredentialBackends: map[string]logical.Factory{
			"userpass": credUserpass.Factory,
		},
		AuditBackends: map[string]audit.Factory{
			"file": audit.NewFileBackend,
		},
		LogicalBackends: map[string]logical.Factory{
			"database":       database.Factory,
			"generic-leased": vault.LeasedPassthroughBackendFactory,
			"pki":            pki.Factory,
			"transit":        transit.Factory,
		},
		BuiltinRegistry: builtinplugins.Registry,
	})
}

// testVaultServerCoreConfig creates a new vault cluster with the given core
// configuration. This is a lower-level test helper.
func testVaultServerCoreConfig(t testing.TB, coreConfig *vault.CoreConfig) (*api.Client, []string, func()) {
	t.Helper()

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: http.Handler,
		NumCores:    1,
	})
	cluster.Start()

	// Make it easy to get access to the active
	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)

	// Get the client already setup for us!
	client := cluster.Cores[0].Client
	client.SetToken(cluster.RootToken)

	// Convert the unseal keys to base64 encoded, since these are how the user
	// will get them.
	unsealKeys := make([]string, len(cluster.BarrierKeys))
	for i := range unsealKeys {
		unsealKeys[i] = base64.StdEncoding.EncodeToString(cluster.BarrierKeys[i])
	}

	return client, unsealKeys, func() { defer cluster.Cleanup() }
}

func TestTransit_Kyber_EncryptDecrypt_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		typ  string
	}{
		{"kyber512", "kyber512"},
		{"kyber768", "kyber768"},
		{"kyber1024", "kyber1024"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			client, _, closer := testVaultServerUnseal(t)
			defer closer()

			if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
				t.Fatalf("mount transit: %v", err)
			}

			keyName := "test-" + c.name
			if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{
				"type": c.typ,
			}); err != nil {
				t.Fatalf("create kyber key: %v", err)
			}

			msg := "hello " + c.name
			enc, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
				"plaintext": base64.StdEncoding.EncodeToString([]byte(msg)),
			})
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			ct, _ := enc.Data["ciphertext"].(string)
			if ct == "" {
				t.Fatalf("encrypt returned empty ciphertext")
			}

			dec, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{
				"ciphertext": ct,
			})
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}

			gotB64, _ := dec.Data["plaintext"].(string)
			got, err := base64.StdEncoding.DecodeString(gotB64)
			if err != nil {
				t.Fatalf("decode plaintext: %v", err)
			}

			if string(got) != msg {
				t.Fatalf("round-trip mismatch: got %q, want %q", got, msg)
			}
		})
	}
}

func TestTransit_Kyber_Rotate_WithAssociatedData(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		typ  string
	}{
		{"kyber512", "kyber512"},
		{"kyber768", "kyber768"},
		{"kyber1024", "kyber1024"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			client, _, closer := testVaultServerUnseal(t)
			defer closer()

			if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
				t.Fatalf("mount transit: %v", err)
			}
			keyName := "rotate-ad-" + c.name
			if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": c.typ}); err != nil {
				t.Fatalf("create kyber key: %v", err)
			}

			msgV1 := "v1-msg-" + c.name
			adV1 := "ad-v1-" + c.name
			enc1, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
				"plaintext":       base64.StdEncoding.EncodeToString([]byte(msgV1)),
				"associated_data": base64.StdEncoding.EncodeToString([]byte(adV1)),
			})
			if err != nil {
				t.Fatalf("encrypt v1: %v", err)
			}
			ct1, _ := enc1.Data["ciphertext"].(string)
			if ct1 == "" {
				t.Fatalf("encrypt v1 returned empty ciphertext")
			}

			// Rotate -> v2
			if _, err := client.Logical().Write("transit/keys/"+keyName+"/rotate", nil); err != nil {
				t.Fatalf("rotate: %v", err)
			}

			msgV2 := "v2-msg-" + c.name
			adV2 := "ad-v2-" + c.name
			enc2, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
				"plaintext":       base64.StdEncoding.EncodeToString([]byte(msgV2)),
				"associated_data": base64.StdEncoding.EncodeToString([]byte(adV2)),
			})
			if err != nil {
				t.Fatalf("encrypt v2: %v", err)
			}
			ct2, _ := enc2.Data["ciphertext"].(string)
			if ct2 == "" || ct2 == ct1 {
				t.Fatalf("encrypt v2 returned unexpected ciphertext")
			}

			// Decrypt both with correct AD.
			for wantMsg, ct := range map[string]string{msgV1: ct1, msgV2: ct2} {
				ad := adV1
				if wantMsg == msgV2 {
					ad = adV2
				}
				dec, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{
					"ciphertext":      ct,
					"associated_data": base64.StdEncoding.EncodeToString([]byte(ad)),
				})
				if err != nil {
					t.Fatalf("decrypt (%s): %v", wantMsg, err)
				}
				gotB64, _ := dec.Data["plaintext"].(string)
				got, err := base64.StdEncoding.DecodeString(gotB64)
				if err != nil {
					t.Fatalf("decode plaintext: %v", err)
				}
				if string(got) != wantMsg {
					t.Fatalf("mismatch: got %q want %q", got, wantMsg)
				}
			}

			// Wrong AD for v1 must fail.
			if _, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{
				"ciphertext":      ct1,
				"associated_data": base64.StdEncoding.EncodeToString([]byte("wrong-ad")),
			}); err == nil {
				t.Fatalf("decrypt should fail with wrong associated_data (v1)")
			}
		})
	}
}

func TestTransit_Kyber_Batch_WithAssociatedData(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		typ  string
	}{
		{"kyber512", "kyber512"},
		{"kyber768", "kyber768"},
		{"kyber1024", "kyber1024"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			client, _, closer := testVaultServerUnseal(t)
			defer closer()

			if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
				t.Fatalf("mount transit: %v", err)
			}
			keyName := "batch-ad-" + c.name
			if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": c.typ}); err != nil {
				t.Fatalf("create kyber key: %v", err)
			}

			type item struct{ msg, ad string }
			inputs := []item{
				{"one-" + c.name, "ad1-" + c.name},
				{"two-" + c.name, "ad2-" + c.name},
				{"three-" + c.name, "ad3-" + c.name},
			}

			var encBatch []map[string]any
			for _, it := range inputs {
				encBatch = append(encBatch, map[string]any{
					"plaintext":       base64.StdEncoding.EncodeToString([]byte(it.msg)),
					"associated_data": base64.StdEncoding.EncodeToString([]byte(it.ad)),
				})
			}

			enc, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{"batch_input": encBatch})
			if err != nil {
				t.Fatalf("batch encrypt: %v", err)
			}
			rawRes, _ := enc.Data["batch_results"].([]any)
			if len(rawRes) != len(inputs) {
				t.Fatalf("encrypt batch size: got %d want %d", len(rawRes), len(inputs))
			}

			// Prepare decrypt batch with matching AD.
			var decBatch []map[string]any
			for i, r := range rawRes {
				m := r.(map[string]any)
				ct, _ := m["ciphertext"].(string)
				if ct == "" {
					t.Fatalf("batch encrypt[%d] empty ciphertext", i)
				}
				decBatch = append(decBatch, map[string]any{
					"ciphertext":      ct,
					"associated_data": base64.StdEncoding.EncodeToString([]byte(inputs[i].ad)),
				})
			}

			dec, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{"batch_input": decBatch})
			if err != nil {
				t.Fatalf("batch decrypt: %v", err)
			}
			rawDec, _ := dec.Data["batch_results"].([]any)
			if len(rawDec) != len(inputs) {
				t.Fatalf("decrypt batch size: got %d want %d", len(rawDec), len(inputs))
			}
			for i, r := range rawDec {
				m := r.(map[string]any)
				gotB64, _ := m["plaintext"].(string)
				got, err := base64.StdEncoding.DecodeString(gotB64)
				if err != nil {
					t.Fatalf("batch decode[%d]: %v", i, err)
				}
				if string(got) != inputs[i].msg {
					t.Fatalf("batch mismatch[%d]: got %q want %q", i, got, inputs[i].msg)
				}
			}
		})
	}
}

func TestTransit_Kyber_Encrypt_AssociatedData_InvalidBase64_Fails(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		typ  string
	}{
		{"kyber512", "kyber512"},
		{"kyber768", "kyber768"},
		{"kyber1024", "kyber1024"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			client, _, closer := testVaultServerUnseal(t)
			defer closer()

			if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
				t.Fatalf("mount transit: %v", err)
			}
			keyName := "bad-ad-" + c.name
			if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": c.typ}); err != nil {
				t.Fatalf("create kyber key: %v", err)
			}

			_, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
				"plaintext":       base64.StdEncoding.EncodeToString([]byte("msg-" + c.name)),
				"associated_data": "NOT-BASE64!!",
			})
			if err == nil {
				t.Fatalf("encrypt should fail for invalid base64 associated_data")
			}
		})
	}
}

// Batch decrypt should fail the entire request if any item's associated_data is wrong.
func TestTransit_Kyber_Batch_WithAssociatedData_MismatchFailsWholeRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		typ  string
	}{
		{"kyber512", "kyber512"},
		{"kyber768", "kyber768"},
		{"kyber1024", "kyber1024"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			client, _, closer := testVaultServerUnseal(t)
			defer closer()

			if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
				t.Fatalf("mount transit: %v", err)
			}
			keyName := "batch-ad-mismatch-" + c.name
			if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": c.typ}); err != nil {
				t.Fatalf("create kyber key: %v", err)
			}

			type item struct{ msg, ad string }
			inputs := []item{
				{"one-" + c.name, "ad1-" + c.name},
				{"two-" + c.name, "ad2-" + c.name}, // we'll mismatch this one
				{"three-" + c.name, "ad3-" + c.name},
			}

			// Encrypt batch with per-item associated_data.
			var encBatch []map[string]any
			for _, it := range inputs {
				encBatch = append(encBatch, map[string]any{
					"plaintext":       base64.StdEncoding.EncodeToString([]byte(it.msg)),
					"associated_data": base64.StdEncoding.EncodeToString([]byte(it.ad)),
				})
			}
			enc, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{"batch_input": encBatch})
			if err != nil {
				t.Fatalf("batch encrypt: %v", err)
			}
			rawRes, _ := enc.Data["batch_results"].([]any)
			if len(rawRes) != len(inputs) {
				t.Fatalf("encrypt batch size: got %d want %d", len(rawRes), len(inputs))
			}

			// Build decrypt batch, intentionally wrong AD for index 1 → whole request should fail.
			var decBatch []map[string]any
			for i, r := range rawRes {
				m := r.(map[string]any)
				ct, _ := m["ciphertext"].(string)
				if ct == "" {
					t.Fatalf("batch encrypt[%d] empty ciphertext", i)
				}
				ad := inputs[i].ad
				if i == 1 {
					ad = "WRONG-" + ad
				}
				decBatch = append(decBatch, map[string]any{
					"ciphertext":      ct,
					"associated_data": base64.StdEncoding.EncodeToString([]byte(ad)),
				})
			}

			dec, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{"batch_input": decBatch})
			if err == nil || dec != nil {
				t.Fatalf("batch decrypt should fail the whole request when any associated_data is wrong")
			}
		})
	}
}

func TestTransit_Kyber_Rewrap_AdvancesVersion(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-rewrap"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber768"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	enc1, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if err != nil {
		t.Fatalf("encrypt v1: %v", err)
	}
	ct1, _ := enc1.Data["ciphertext"].(string)
	if ct1 == "" {
		t.Fatalf("encrypt v1 returned empty ciphertext")
	}

	// rotate → v2
	if _, err := client.Logical().Write("transit/keys/"+keyName+"/rotate", nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// rewrap v1 → v2
	rw, err := client.Logical().Write("transit/rewrap/"+keyName, map[string]any{"ciphertext": ct1})
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	ct2, _ := rw.Data["ciphertext"].(string)
	if ct2 == "" || ct2 == ct1 {
		t.Fatalf("rewrap should change ciphertext")
	}

	// decrypt rewrapped under latest
	dec, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{"ciphertext": ct2})
	if err != nil {
		t.Fatalf("decrypt rewrapped: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(dec.Data["plaintext"].(string))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q want %q", got, "hello")
	}
}

func TestTransit_Kyber_MinDecryptionVersion_BlocksOld(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-mindec"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber512"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	enc1, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString([]byte("v1")),
	})
	if err != nil {
		t.Fatalf("encrypt v1: %v", err)
	}
	ct1, _ := enc1.Data["ciphertext"].(string)

	// rotate to v2 and forbid decrypting v1
	if _, err := client.Logical().Write("transit/keys/"+keyName+"/rotate", nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := client.Logical().Write("transit/keys/"+keyName+"/config", map[string]any{"min_decryption_version": 2}); err != nil {
		t.Fatalf("set min_decryption_version: %v", err)
	}

	if _, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{"ciphertext": ct1}); err == nil {
		t.Fatalf("expected decrypt of v1 to fail when min_decryption_version=2")
	}
}

func TestTransit_Kyber_InvalidOrTamperedCiphertext_Fails(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-badct"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber768"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	// Invalid base64 ciphertext
	if _, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{"ciphertext": "NOT-BASE64!!"}); err == nil {
		t.Fatalf("expected error for invalid base64 ciphertext")
	}

	// Create a valid ciphertext…
	enc, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct, _ := enc.Data["ciphertext"].(string)
	if ct == "" {
		t.Fatalf("encrypt returned empty ciphertext")
	}

	// …then tamper inside the payload but keep base64 valid.
	idx := strings.LastIndex(ct, ":")
	if idx < 0 {
		t.Skip("unexpected ciphertext format (no prefix delimiter)")
	}
	prefix, payloadB64 := ct[:idx+1], ct[idx+1:]
	raw, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	raw[len(raw)-1] ^= 0x01 // flip a bit
	tampered := prefix + base64.StdEncoding.EncodeToString(raw)

	if _, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{"ciphertext": tampered}); err == nil {
		t.Fatalf("expected auth failure for tampered ciphertext")
	}
}

func TestTransit_Kyber_NonDeterministic_And_CrossKey_Fail(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	if _, err := client.Logical().Write("transit/keys/a", map[string]any{"type": "kyber1024"}); err != nil {
		t.Fatalf("create key a: %v", err)
	}
	if _, err := client.Logical().Write("transit/keys/b", map[string]any{"type": "kyber1024"}); err != nil {
		t.Fatalf("create key b: %v", err)
	}

	enc1, err := client.Logical().Write("transit/encrypt/a", map[string]any{
		"plaintext":       base64.StdEncoding.EncodeToString([]byte("same")),
		"associated_data": base64.StdEncoding.EncodeToString([]byte("ad")),
	})
	if err != nil {
		t.Fatalf("encrypt1: %v", err)
	}
	enc2, err := client.Logical().Write("transit/encrypt/a", map[string]any{
		"plaintext":       base64.StdEncoding.EncodeToString([]byte("same")),
		"associated_data": base64.StdEncoding.EncodeToString([]byte("ad")),
	})
	if err != nil {
		t.Fatalf("encrypt2: %v", err)
	}
	if enc1.Data["ciphertext"].(string) == enc2.Data["ciphertext"].(string) {
		t.Fatalf("encryption should be non-deterministic")
	}

	// Decrypt with wrong key must fail.
	if _, err := client.Logical().Write("transit/decrypt/b", map[string]any{
		"ciphertext": enc1.Data["ciphertext"].(string),
	}); err == nil {
		t.Fatalf("expected decrypt with wrong key to fail")
	}
}

// Encrypt should fail when plaintext is not valid base64.
func TestTransit_Kyber_Encrypt_InvalidBase64Plaintext_Fails(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-bad-pt"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber768"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	// plaintext must be base64-encoded; this should error.
	if _, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
		"plaintext": "NOT-BASE64!!",
	}); err == nil {
		t.Fatalf("encrypt should fail for invalid base64 plaintext")
	}
}

// Decrypt should fail when required field "ciphertext" is missing (or empty).
func TestTransit_Kyber_Decrypt_MissingCiphertext_Fails(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-missing-ct"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber512"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	// Missing "ciphertext"
	if _, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{}); err == nil {
		t.Fatalf("decrypt should fail when ciphertext is missing")
	}

	// Explicit empty "ciphertext"
	if _, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{
		"ciphertext": "",
	}); err == nil {
		t.Fatalf("decrypt should fail when ciphertext is empty")
	}
}

// Rewrap must fail if original encrypt used associated_data but rewrap omits or mismatches it.
func TestTransit_Kyber_Rewrap_MissingOrWrongAssociatedData_Fails(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-rewrap-ad"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber1024"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	// Encrypt with AD.
	ad := "ad-rewrap"
	enc, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
		"plaintext":       base64.StdEncoding.EncodeToString([]byte("hello-ad")),
		"associated_data": base64.StdEncoding.EncodeToString([]byte(ad)),
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct, _ := enc.Data["ciphertext"].(string)
	if ct == "" {
		t.Fatalf("encrypt returned empty ciphertext")
	}

	// Rotate to introduce a new version, so rewrap is meaningful.
	if _, err := client.Logical().Write("transit/keys/"+keyName+"/rotate", nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Rewrap WITHOUT AD → must fail (AD is required to decrypt before re-encrypt).
	if _, err := client.Logical().Write("transit/rewrap/"+keyName, map[string]any{
		"ciphertext": ct,
	}); err == nil {
		t.Fatalf("rewrap should fail when associated_data is required but missing")
	}

	// Rewrap WITH WRONG AD → must also fail.
	if _, err := client.Logical().Write("transit/rewrap/"+keyName, map[string]any{
		"ciphertext":      ct,
		"associated_data": base64.StdEncoding.EncodeToString([]byte("wrong-ad")),
	}); err == nil {
		t.Fatalf("rewrap should fail with wrong associated_data")
	}
}

func TestTransit_Kyber_BatchEncrypt_InvalidBase64AssociatedData_FailsWholeRequest(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-batch-bad-ad"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber768"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	batch := []map[string]any{
		{
			"plaintext":       base64.StdEncoding.EncodeToString([]byte("ok-1")),
			"associated_data": base64.StdEncoding.EncodeToString([]byte("ad-1")),
		},
		{
			"plaintext":       base64.StdEncoding.EncodeToString([]byte("bad-2")),
			"associated_data": "NOT-BASE64!!", // should poison the whole batch
		},
		{
			"plaintext":       base64.StdEncoding.EncodeToString([]byte("ok-3")),
			"associated_data": base64.StdEncoding.EncodeToString([]byte("ad-3")),
		},
	}

	if resp, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{"batch_input": batch}); err == nil || resp != nil {
		t.Fatalf("batch encrypt should fail entire request when one item has invalid base64 associated_data")
	}
}

func TestTransit_Kyber_EmptyPlaintext_RoundTrip(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-empty-pt"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber768"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	enc, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{"plaintext": ""})
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	ct, _ := enc.Data["ciphertext"].(string)
	if ct == "" {
		t.Fatalf("encrypt returned empty ciphertext")
	}

	dec, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{"ciphertext": ct})
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	gotB64, _ := dec.Data["plaintext"].(string)
	got, err := base64.StdEncoding.DecodeString(gotB64)
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got non-empty bytes for empty plaintext: %d", len(got))
	}
}

func TestTransit_Kyber_LargePlaintext_RoundTrip(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-large-pt"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber768"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	plaintext := bytes.Repeat([]byte("x"), 1<<19) // 512 KiB
	enc, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		t.Fatalf("encrypt large: %v", err)
	}
	ct, _ := enc.Data["ciphertext"].(string)
	if ct == "" {
		t.Fatalf("encrypt large returned empty ciphertext")
	}

	dec, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{"ciphertext": ct})
	if err != nil {
		t.Fatalf("decrypt large: %v", err)
	}
	gotB64, _ := dec.Data["plaintext"].(string)
	got, err := base64.StdEncoding.DecodeString(gotB64)
	if err != nil {
		t.Fatalf("decode large: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("large round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}
}

func TestTransit_Kyber_Batch_MixedAssociatedData(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-batch-mixed-ad"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber768"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	type item struct {
		msg string
		ad  *string
	}
	ad1 := "ad-1"
	ad3 := "ad-3"
	inputs := []item{
		{msg: "one", ad: &ad1},
		{msg: "two", ad: nil},
		{msg: "three", ad: &ad3},
	}

	var encBatch []map[string]any
	for _, it := range inputs {
		m := map[string]any{
			"plaintext": base64.StdEncoding.EncodeToString([]byte(it.msg)),
		}
		if it.ad != nil {
			m["associated_data"] = base64.StdEncoding.EncodeToString([]byte(*it.ad))
		}
		encBatch = append(encBatch, m)
	}

	enc, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{"batch_input": encBatch})
	if err != nil {
		t.Fatalf("batch encrypt: %v", err)
	}
	rawRes, _ := enc.Data["batch_results"].([]any)
	if len(rawRes) != len(inputs) {
		t.Fatalf("encrypt batch size: got %d want %d", len(rawRes), len(inputs))
	}

	var decBatch []map[string]any
	for i, r := range rawRes {
		m := r.(map[string]any)
		ct, _ := m["ciphertext"].(string)
		if ct == "" {
			t.Fatalf("batch encrypt[%d] empty ciphertext", i)
		}
		d := map[string]any{"ciphertext": ct}
		if inputs[i].ad != nil {
			d["associated_data"] = base64.StdEncoding.EncodeToString([]byte(*inputs[i].ad))
		}
		decBatch = append(decBatch, d)
	}

	dec, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{"batch_input": decBatch})
	if err != nil {
		t.Fatalf("batch decrypt: %v", err)
	}
	rawDec, _ := dec.Data["batch_results"].([]any)
	if len(rawDec) != len(inputs) {
		t.Fatalf("decrypt batch size: got %d want %d", len(rawDec), len(inputs))
	}
	for i, r := range rawDec {
		m := r.(map[string]any)
		gotB64, _ := m["plaintext"].(string)
		got, err := base64.StdEncoding.DecodeString(gotB64)
		if err != nil {
			t.Fatalf("batch decode[%d]: %v", i, err)
		}
		if string(got) != inputs[i].msg {
			t.Fatalf("batch mismatch[%d]: got %q want %q", i, got, inputs[i].msg)
		}
	}
}

func TestTransit_Kyber_Concurrency_Smoke(t *testing.T) {
	t.Parallel()

	client, _, closer := testVaultServerUnseal(t)
	defer closer()

	if err := client.Sys().Mount("transit", &api.MountInput{Type: "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	const keyName = "kyber-concurrency"
	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]any{"type": "kyber768"}); err != nil {
		t.Fatalf("create kyber key: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	workers := 50
	iters := 50
	wg.Add(workers)
	for g := 0; g < workers; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				msg := "race-msg"
				ad := "race-ad"

				enc, err := client.Logical().Write("transit/encrypt/"+keyName, map[string]any{
					"plaintext":       base64.StdEncoding.EncodeToString([]byte(msg)),
					"associated_data": base64.StdEncoding.EncodeToString([]byte(ad)),
				})
				if err != nil {
					errCh <- fmt.Errorf("encrypt: %w", err)
					return
				}
				ct, _ := enc.Data["ciphertext"].(string)
				if ct == "" {
					errCh <- fmt.Errorf("empty ciphertext")
					return
				}

				dec, err := client.Logical().Write("transit/decrypt/"+keyName, map[string]any{
					"ciphertext":      ct,
					"associated_data": base64.StdEncoding.EncodeToString([]byte(ad)),
				})
				if err != nil {
					errCh <- fmt.Errorf("decrypt: %w", err)
					return
				}
				gotB64, _ := dec.Data["plaintext"].(string)
				got, err := base64.StdEncoding.DecodeString(gotB64)
				if err != nil {
					errCh <- fmt.Errorf("decode: %w", err)
					return
				}
				if string(got) != msg {
					errCh <- fmt.Errorf("mismatch: got %q want %q", got, msg)
					return
				}
			}
		}()
	}
	wg.Wait()

	select {
	case err := <-errCh:
		t.Fatalf("concurrency error: %v", err)
	default:
	}
}

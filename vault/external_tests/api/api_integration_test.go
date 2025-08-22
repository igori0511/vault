// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/base64"
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

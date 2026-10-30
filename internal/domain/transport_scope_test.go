package domain

import "testing"

// testTransportInputClaims is the admitted mandatory TRUE transport-input claim
// that grounds transport-peer scope.
func testTransportInputClaims(mandatory ConditionID) ([]ConditionID, []Claim) {
	return []ConditionID{mandatory}, []Claim{{
		ID:           "CL-" + ClaimID(mandatory),
		ConditionID:  mandatory,
		Result:       ClaimTrue,
		Producer:     "evaluator.ServerTransportInput",
		ControlBasis: ControlBasisTransportPeerInput,
		Limitations:  TransportPeerScopeLimitations(),
	}}
}

func TestTransportScopeContract(t *testing.T) {
	t.Run("scope constants are frozen", func(t *testing.T) {
		if ScopeTransportPeer != "transport-peer" {
			t.Fatalf("scope = %q, want transport-peer", ScopeTransportPeer)
		}
		if ControlBasisTransportPeerInput != "transport-peer-input" {
			t.Fatalf("control basis = %q, want transport-peer-input", ControlBasisTransportPeerInput)
		}
		wantLimitation := "Transport-peer scope: a client of the product's affected transport can supply the triggering input. Whether an adversary can access that transport—through socket permissions, placement, ingress or authentication—is not established."
		if TransportPeerScopeLimitation != wantLimitation {
			t.Fatalf("limitation = %q", TransportPeerScopeLimitation)
		}
	})

	t.Run("transport-peer is an orthogonal scope, not a verdict or profile", func(t *testing.T) {
		if ScopeTransportPeer == ScopeLibraryAPI {
			t.Fatal("transport-peer must stay distinct from library-api")
		}
		if !KnownExploitabilityScope(ScopeTransportPeer) || !KnownExploitabilityScope(ScopeLibraryAPI) {
			t.Fatal("both frozen scopes must be known")
		}
		if KnownExploitabilityScope("deployment") || KnownExploitabilityScope("") {
			t.Fatal("unknown scopes must be rejected")
		}
		for _, verdict := range []Verdict{
			VerdictExploitable, VerdictNotAffected, VerdictNoExploitPathFound, VerdictInconclusive,
		} {
			if string(verdict) == string(ScopeTransportPeer) {
				t.Fatalf("scope collides with verdict %q", verdict)
			}
		}
		for _, profile := range []ThreatProfile{ProfileZeroTrust, ProfileClusterPerimeter} {
			if string(profile) == string(ScopeTransportPeer) {
				t.Fatalf("scope collides with profile %q", profile)
			}
		}
		for _, outcome := range []AssessmentOutcome{OutcomeDecided, OutcomeExternal, OutcomeFailed} {
			if string(outcome) == string(ScopeTransportPeer) {
				t.Fatalf("scope collides with outcome %q", outcome)
			}
		}
	})

	t.Run("only an admitted mandatory TRUE transport claim grounds the scope", func(t *testing.T) {
		mandatory, claims := testTransportInputClaims("C-TRIGGER")
		if !TransportPeerScopeAdmitted(mandatory, claims) {
			t.Fatal("a mandatory TRUE transport-input claim must ground the scope")
		}

		cases := []struct {
			name      string
			mandatory []ConditionID
			claims    []Claim
		}{
			{"no mandatory conjunction", nil, claims},
			{"empty mandatory conjunction", []ConditionID{}, claims},
			{"no claims", mandatory, nil},
			{
				name:      "claim is not mandatory",
				mandatory: []ConditionID{"C-OTHER"},
				claims:    claims,
			},
			{
				name:      "claim is unknown",
				mandatory: mandatory,
				claims:    []Claim{{ConditionID: "C-TRIGGER", Result: ClaimUnknown, ControlBasis: ControlBasisTransportPeerInput}},
			},
			{
				name:      "claim is false",
				mandatory: mandatory,
				claims:    []Claim{{ConditionID: "C-TRIGGER", Result: ClaimFalse, ControlBasis: ControlBasisTransportPeerInput}},
			},
			{
				name:      "claim has no control basis",
				mandatory: mandatory,
				claims:    []Claim{{ConditionID: "C-TRIGGER", Result: ClaimTrue}},
			},
			{
				name:      "claim carries the library basis",
				mandatory: mandatory,
				claims:    []Claim{{ConditionID: "C-TRIGGER", Result: ClaimTrue, ControlBasis: ControlBasisLibraryPublicAPI}},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if TransportPeerScopeAdmitted(tc.mandatory, tc.claims) {
					t.Fatal("scope must not be grounded")
				}
			})
		}
	})

	t.Run("a supporting transport input claim does not scope the verdict", func(t *testing.T) {
		mandatory := []ConditionID{"C-TRIGGER"}
		claims := []Claim{
			{ID: "CL-C-SUPPORTING", ConditionID: "C-SUPPORTING", Result: ClaimTrue, ControlBasis: ControlBasisTransportPeerInput},
		}
		if TransportPeerScopeAdmitted(mandatory, claims) {
			t.Fatal("a non-mandatory transport claim must not scope the verdict")
		}
		// A mandatory claim of another basis does not scope it either.
		claims = append(claims, Claim{ID: "CL-C-TRIGGER", ConditionID: "C-TRIGGER", Result: ClaimTrue})
		if TransportPeerScopeAdmitted(mandatory, claims) {
			t.Fatal("a mandatory TRUE claim without the transport basis must not scope the verdict")
		}
	})

	t.Run("mandatory limitation slices are fresh on every call", func(t *testing.T) {
		first := ExploitabilityScopeLimitations(ScopeTransportPeer)
		if len(first) != 1 || first[0] != TransportPeerScopeLimitation {
			t.Fatalf("transport limitations = %v", first)
		}
		first[0] = "mutated"
		if ExploitabilityScopeLimitations(ScopeTransportPeer)[0] != TransportPeerScopeLimitation {
			t.Fatal("a returned limitation slice must not alias shared state")
		}

		transport := TransportPeerScopeLimitations()
		transport[0] = "mutated"
		if TransportPeerScopeLimitations()[0] != TransportPeerScopeLimitation {
			t.Fatal("TransportPeerScopeLimitations must return a fresh slice")
		}

		library := ExploitabilityScopeLimitations(ScopeLibraryAPI)
		if len(library) != 1 || library[0] != LibraryAPIScopeLimitation {
			t.Fatalf("library limitations = %v", library)
		}
		if got := ExploitabilityScopeLimitations(""); got != nil {
			t.Fatalf("an unscoped conclusion carries no limitation, got %v", got)
		}
	})

	t.Run("perimeter bases are typed and frozen", func(t *testing.T) {
		want := map[PerimeterBasis]string{
			PerimeterBasisUnknown:            "unknown",
			PerimeterBasisListenerLocality:   "listener-locality",
			PerimeterBasisDeploymentTopology: "deployment-topology",
			PerimeterBasisDeploymentPolicy:   "deployment-policy",
			PerimeterBasisOperatorDeclared:   "operator-declared",
		}
		for basis, text := range want {
			if string(basis) != text {
				t.Fatalf("basis = %q, want %q", basis, text)
			}
			if !basis.Valid() {
				t.Fatalf("%q must be valid", basis)
			}
		}
		if PerimeterBasis("loopback").Valid() {
			t.Fatal("unknown bases must be rejected")
		}

		trusting := map[PerimeterBasis]bool{
			PerimeterBasisUnknown:            false,
			PerimeterBasisListenerLocality:   false,
			PerimeterBasisDeploymentTopology: false,
			PerimeterBasisDeploymentPolicy:   true,
			PerimeterBasisOperatorDeclared:   true,
		}
		for basis, admits := range trusting {
			if basis.AdmitsTrust() != admits {
				t.Fatalf("%q admits trust = %v, want %v", basis, basis.AdmitsTrust(), admits)
			}
		}
	})

	t.Run("listener locality never selects a trusted-peer profile", func(t *testing.T) {
		locality := NewPerimeterAssessment(PerimeterClusterInternal, PerimeterBasisListenerLocality, "unix socket and loopback listeners")
		if locality.AllowsTrustedPeerSelection() {
			t.Fatal("listener locality must not select trust")
		}
		if !hasLimitation(locality.Limitations, PerimeterLocalityNotTrustLimitation) {
			t.Fatalf("locality assessment must carry the locality-not-trust limitation: %v", locality.Limitations)
		}
		if err := locality.Validate(); err != nil {
			t.Fatalf("locality assessment: %v", err)
		}

		topology := NewPerimeterAssessment(PerimeterClusterInternal, PerimeterBasisDeploymentTopology, "ClusterIP service")
		if topology.AllowsTrustedPeerSelection() {
			t.Fatal("a topology basis is not a trust basis")
		}
		if err := topology.Validate(); err != nil {
			t.Fatalf("topology assessment: %v", err)
		}

		declared := NewPerimeterAssessment(PerimeterClusterInternal, PerimeterBasisOperatorDeclared, "--perimeter cluster-internal")
		if !declared.AllowsTrustedPeerSelection() {
			t.Fatal("an explicit operator declaration may select trust")
		}
		if err := declared.Validate(); err != nil {
			t.Fatalf("operator-declared assessment: %v", err)
		}

		policy := NewPerimeterAssessment(PerimeterClusterInternal, PerimeterBasisDeploymentPolicy, "admitted network policy")
		if !policy.AllowsTrustedPeerSelection() {
			t.Fatal("an admitted deployment policy may select trust")
		}

		public := NewPerimeterAssessment(PerimeterPublic, PerimeterBasisOperatorDeclared, "public bind")
		if public.AllowsTrustedPeerSelection() {
			t.Fatal("a public perimeter never selects trust")
		}
	})

	t.Run("malformed perimeter assessments are rejected", func(t *testing.T) {
		var absent *PerimeterAssessment
		if absent.AllowsTrustedPeerSelection() {
			t.Fatal("a nil assessment must not select trust")
		}
		mustFail(t, absent.Validate(), "nil assessment")

		// A cluster-internal classification built without the constructor must
		// still carry the limitation.
		raw := &PerimeterAssessment{Perimeter: PerimeterClusterInternal, Basis: PerimeterBasisListenerLocality}
		mustFail(t, raw.Validate(), "locality-not-trust limitation")

		unknownPerimeter := NewPerimeterAssessment("intranet", PerimeterBasisOperatorDeclared, "")
		mustFail(t, unknownPerimeter.Validate(), "unknown perimeter")

		unknownBasis := NewPerimeterAssessment(PerimeterClusterInternal, "loopback", "")
		mustFail(t, unknownBasis.Validate(), "unknown basis")
	})
}

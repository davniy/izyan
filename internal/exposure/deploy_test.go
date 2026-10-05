package exposure

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestScanDeploy(t *testing.T) {
	root := t.TempDir()
	mk := func(p, content string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("helm/app/templates/service.yaml", `apiVersion: v1
kind: Service
metadata:
  name: app
spec:
  type: LoadBalancer
  ports:
  - port: 443
`)
	mk("helm/app/templates/ingress.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
  - host: api.example.com
`)
	mk("k8s/pod.yaml", `kind: Deployment
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - ports:
        - hostPort: 9090
`)
	mk("docker-compose.yml", `services:
  app:
    ports:
      - "8080:8080"
`)
	// Outside deploy scope — must be ignored.
	mk("config/app.yaml", "kind: Service\nspec:\n  type: LoadBalancer\n")
	mk("tests/fixtures/svc.yaml", "kind: Ingress\nspec:\n  rules:\n  - host: x\n")

	facts, err := ScanDeploy(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range facts {
		got[f.Target]++
		if f.Kind != "deployment" || f.Direction != "inbound" {
			t.Fatalf("bad fact: %+v", f)
		}
		if f.Scope != domain.ScopeAllInterfaces {
			t.Fatalf("deployment fact without public scope: %+v", f)
		}
	}
	want := map[string]int{
		"k8s:Service:LoadBalancer": 1,
		"k8s:Ingress":              1,
		"k8s:hostNetwork":          1,
		"k8s:hostPort":             1,
		"compose:published-port":   1,
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("target %s count=%d want %d (all: %v)", k, got[k], n, got)
		}
	}
	var ing *domain.ExposureFact
	for i, f := range facts {
		if f.Target == "k8s:Ingress" {
			ing = &facts[i]
		}
	}
	if ing == nil || ing.Address != "api.example.com" {
		t.Fatalf("ingress host not resolved: %+v", ing)
	}
}

func TestScanDeploy_ClusterIPAndIstioAuth(t *testing.T) {
	root := t.TempDir()
	mk := func(p, content string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Kubernetes Service of type ClusterIP (cluster-internal mesh service)
	mk("deploy/service-internal.yaml", `apiVersion: v1
kind: Service
metadata:
  name: internal-svc
spec:
  type: ClusterIP
  ports:
  - port: 8080
`)

	// 2. Istio AuthorizationPolicy (inbound auth middleware)
	mk("deploy/auth-policy.yaml", `apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: require-jwt
spec:
  action: ALLOW
`)

	// 3. Istio RequestAuthentication (inbound auth middleware)
	mk("deploy/req-auth.yaml", `apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
`)

	facts, err := ScanDeploy(root)
	if err != nil {
		t.Fatal(err)
	}

	var foundClusterIP, foundAuthPolicy, foundReqAuth bool
	for _, f := range facts {
		if f.Target == "k8s:Service:ClusterIP" {
			foundClusterIP = true
			if f.Scope != domain.ScopeLoopback {
				t.Errorf("ClusterIP scope=%s, want %s", f.Scope, domain.ScopeLoopback)
			}
		}
		if f.Target == "istio:AuthorizationPolicy" {
			foundAuthPolicy = true
			if f.Kind != "auth-middleware" || f.Direction != "inbound" {
				t.Errorf("AuthorizationPolicy fact kind=%s dir=%s, want auth-middleware inbound", f.Kind, f.Direction)
			}
		}
		if f.Target == "istio:RequestAuthentication" {
			foundReqAuth = true
			if f.Kind != "auth-middleware" || f.Direction != "inbound" {
				t.Errorf("RequestAuthentication fact kind=%s dir=%s, want auth-middleware inbound", f.Kind, f.Direction)
			}
		}
	}

	if !foundClusterIP {
		t.Errorf("k8s:Service:ClusterIP fact not found in %+v", facts)
	}
	if !foundAuthPolicy {
		t.Errorf("istio:AuthorizationPolicy fact not found in %+v", facts)
	}
	if !foundReqAuth {
		t.Errorf("istio:RequestAuthentication fact not found in %+v", facts)
	}
}

func TestScanDeployWithOptions_Archive(t *testing.T) {
	tempDir := t.TempDir()
	tgzData, err := createMockTGZ(map[string]string{
		"mychart/templates/service.yaml": `apiVersion: v1
kind: Service
metadata:
  name: internal-svc
spec:
  type: ClusterIP
  ports:
  - port: 8080
`,
	})
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(tempDir, "mychart-1.0.0.tgz")
	if err := os.WriteFile(archivePath, tgzData, 0o644); err != nil {
		t.Fatal(err)
	}

	facts, err := ScanDeployWithOptions(DeployScanOptions{
		ArchivePath: archivePath,
	})
	if err != nil {
		t.Fatalf("ScanDeployWithOptions failed: %v", err)
	}

	found := false
	for _, f := range facts {
		if f.Target == "k8s:Service:ClusterIP" {
			found = true
			if f.Scope != domain.ScopeLoopback {
				t.Errorf("scope = %s, want %s", f.Scope, domain.ScopeLoopback)
			}
		}
	}
	if !found {
		t.Fatalf("expected k8s:Service:ClusterIP fact, got %+v", facts)
	}
}

func TestScanDeployWithOptions_ExtraPaths(t *testing.T) {
	repoDir := t.TempDir()
	extraDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(repoDir, "docker-compose.yml"), []byte(`services:
  app:
    ports:
      - "8080:8080"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(extraDir, "service.yaml"), []byte(`apiVersion: v1
kind: Service
metadata:
  name: extra-svc
spec:
  type: LoadBalancer
  ports:
  - port: 443
`), 0o644); err != nil {
		t.Fatal(err)
	}

	facts, err := ScanDeployWithOptions(DeployScanOptions{
		RootPath:   repoDir,
		ExtraPaths: []string{extraDir},
	})
	if err != nil {
		t.Fatalf("ScanDeployWithOptions failed: %v", err)
	}

	var foundCompose, foundLB bool
	for _, f := range facts {
		if f.Target == "compose:published-port" {
			foundCompose = true
		}
		if f.Target == "k8s:Service:LoadBalancer" {
			foundLB = true
		}
	}
	if !foundCompose {
		t.Errorf("expected compose:published-port fact, got %+v", facts)
	}
	if !foundLB {
		t.Errorf("expected k8s:Service:LoadBalancer fact, got %+v", facts)
	}
}

func TestScanDeployWithOptions_AutoDiscovery(t *testing.T) {
	parentDir := t.TempDir()
	repoDir := filepath.Join(parentDir, "app")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// 1. Chart archive in root
	tgzData, err := createMockTGZ(map[string]string{
		"chart/templates/ingress.yaml": `apiVersion: networking.k8s.io/v1
kind: Ingress
spec:
  rules:
  - host: autodiscover.example.com
`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "app-0.1.0.tgz"), tgzData, 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Sibling directory app-deploy
	siblingDir := filepath.Join(parentDir, "app-deploy")
	if err := os.MkdirAll(siblingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(siblingDir, "service.yaml"), []byte(`apiVersion: v1
kind: Service
metadata:
  name: sibling-svc
spec:
  type: NodePort
  ports:
  - nodePort: 30080
`), 0o644); err != nil {
		t.Fatal(err)
	}

	facts, err := ScanDeployWithOptions(DeployScanOptions{
		RootPath: repoDir,
	})
	if err != nil {
		t.Fatalf("ScanDeployWithOptions failed: %v", err)
	}

	var foundIngress, foundNodePort bool
	for _, f := range facts {
		if f.Target == "k8s:Ingress" && f.Address == "autodiscover.example.com" {
			foundIngress = true
		}
		if f.Target == "k8s:Service:NodePort" {
			foundNodePort = true
		}
	}

	if !foundIngress {
		t.Errorf("expected autodiscovered Ingress fact from root archive, got %+v", facts)
	}
	if !foundNodePort {
		t.Errorf("expected autodiscovered NodePort fact from sibling app-deploy, got %+v", facts)
	}
}

func TestScanDeployWithOptions_Deduplication(t *testing.T) {
	repoDir := t.TempDir()
	extraDir := t.TempDir()

	svcYAML := `apiVersion: v1
kind: Service
metadata:
  name: svc
spec:
  type: LoadBalancer
  ports:
  - port: 80
`
	if err := os.MkdirAll(filepath.Join(repoDir, "deploy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "deploy", "svc.yaml"), []byte(svcYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extraDir, "svc.yaml"), []byte(svcYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	facts, err := ScanDeployWithOptions(DeployScanOptions{
		RootPath:   repoDir,
		ExtraPaths: []string{extraDir},
	})
	if err != nil {
		t.Fatal(err)
	}

	lbCount := 0
	for _, f := range facts {
		if f.Target == "k8s:Service:LoadBalancer" {
			lbCount++
		}
	}
	if lbCount != 1 {
		t.Fatalf("expected exactly 1 LoadBalancer fact after deduplication, got %d", lbCount)
	}
}

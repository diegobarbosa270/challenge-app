import subprocess
import time
import statistics
import argparse
import json
import http.client
import base64
import requests
import json

def open_qod(msisdn):
    # Função para realizar chamadas HTTP sequenciais

    # URL base para as chamadas de autenticação
    auth_base_url = "https://auth.br-pro.baikalplatform.com"
    # URL base para a API
    api_base_url = "https://api.br-pro.baikalplatform.com"

    # Cabeçalhos comuns para as chamadas de autenticação
    auth_headers = {
        'Content-Type': "application/x-www-form-urlencoded",
        'Authorization': "Basic dml2b19pdGF1LXBvYzpGQUNDb2Uxa210YmFKM1ZHSnNtag=="
    }

    # 1. CHAMADA DE CIBA PARA OBTER AUTH_REQ_ID
    payload = f"purpose=dpv%3ARequestedServiceProvision%23qod&login_hint=tel%3A%2B{msisdn}"
    response = requests.post(f"{auth_base_url}/bc-authorize", data=payload, headers=auth_headers)
    response_data = response.json()
    auth_req_id = response_data.get('auth_req_id')
    # print("Auth Request ID Genereated", auth_req_id)

    # 2. CHAMADA PARA BUSCAR O TOKEN
    payload = f"grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba&auth_req_id={auth_req_id}"
    response = requests.post(f"{auth_base_url}/token", data=payload, headers=auth_headers)
    response_data = response.json()
    access_token = response_data.get('access_token')
    # print("Access Token Genereated", access_token)

    # 3. Chamada para abertura de sessão (15 minutos default)
    session_payload = {
        "duration": 900,
        "ueId": {
            "msisdn": f"+{msisdn}"
        },
        "asId": {
            "ipv6addr": "2804:18:1860:3213:1:4:b2fa:d51c"
        },
        "qos": "QOS_E",
        "notificationUri": "https://webhook.site/3c814d13-965b-4d1d-bfa1-4a2ea751e4cb",
        "notificationAuthToken": "c8974e592c2fa383d4a3960666"
    }

    session_headers = {
        'Content-Type': "application/json",
        'Accept': "application/json",
        'Authorization': f"Bearer {access_token}"
    }

    response = requests.post(f"{api_base_url}/qod/v0/sessions", json=session_payload, headers=session_headers)
    response_data = response.json()
    id_session = response_data.get('id')
    print("Session Response Data:", json.dumps(response.json(), indent=4))
    print("Starting Requests...")

    return id_session, access_token

def check_http_support(url, expected_protocol, insecure):
    test_command = [
        "curl",
        "-o", "/dev/null",
        "-s",
        expected_protocol,
        "-w", "%{http_version}",
        url
    ]

    if insecure:
       test_command.insert(1, "--insecure")

    proc = subprocess.Popen(test_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    if proc.returncode == 0:
        http_version = stdout.decode('utf-8').strip()
        if (expected_protocol == "--http1.1" and http_version == "1.1") or \
           (expected_protocol == "--http2" and http_version == "2") or \
           (expected_protocol == "--http3" and http_version.startswith("3")):
            return True
    return False

def run_test(url, protocol, method="POST", post_data=None, headers=None, cookie=None, num_requests=1000, concurrency=10, use_gzip=False, gzip_itau=False, insecure=False, msisdn=None, qod=0):
    
    if qod == 1:
        if not msisdn:
            raise ValueError("msisdn is required when qod is 1")
        msisdn = str(msisdn)
        print("MSISDN", msisdn)
        id_session, access_token = open_qod(msisdn)
        
    http_version_flag = {
        "http1_1": "--http1.1",
        "http2": "--http2",
        "http3": "--http3"
    }

    if protocol not in http_version_flag:
        raise ValueError("Unsupported protocol. Use 'http1_1', 'http2', or 'http3'.")

    if not check_http_support(url, http_version_flag[protocol], insecure):
        print(f"Error: The server does not support {protocol}. Skipping test.")
        return

    gzip_flag = ["--compressed"] if use_gzip else []
    insecure_flag = ["--insecure"] if insecure else []

    curl_command = [
        "curl",
        "-o", "/dev/null",
        "-s",
        "-X", method,
        http_version_flag[protocol],
        *gzip_flag,
        *insecure_flag,
        "-w", (
            "HTTP Code: %{http_code}\n"
            "DNS Lookup: %{time_namelookup}\n"
            "TCP Connect: %{time_connect}\n"
            "SSL Handshake: %{time_appconnect}\n"
            "Pre-Transfer: %{time_pretransfer}\n"
            "TTFB: %{time_starttransfer}\n"
            "Time Total: %{time_total}\n"
            "Download Size: %{size_download}\n"
        ),
        url
    ]

    if post_data:
        curl_command.extend(["-d", post_data])

    if headers:
        for header in headers:
            curl_command.extend(["-H", header])

    # Adiciona o cabeçalho 'X-Accept: itau-compress-response' se --gzip_itau estiver ativado
    if gzip_itau:
        curl_command.extend(["-H", "X-Accept: itau-compress-response"])

    if cookie:
        curl_command.extend(["--cookie", cookie])

    dns_times = []
    connect_times = []
    ssl_times = []
    pretransfer_times = []
    starttransfer_times = []
    total_times = []
    failed_requests = 0
    total_downloaded_bytes = 0

    start_time = time.time()

    for _ in range(num_requests // concurrency):
        procs = []
        for _ in range(concurrency):
            procs.append(subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE))

        for proc in procs:
            stdout, stderr = proc.communicate()
            if proc.returncode == 0:
                output = stdout.decode('utf-8')
                http_code = output.split("HTTP Code: ")[-1].strip()
                if http_code.startswith('2') or http_code.startswith('3'):
                    dns_times.append(float(output.split("DNS Lookup: ")[-1].split()[0]) * 1000)
                    connect_times.append(float(output.split("TCP Connect: ")[-1].split()[0]) * 1000)
                    ssl_times.append(float(output.split("SSL Handshake: ")[-1].split()[0]) * 1000)
                    pretransfer_times.append(float(output.split("Pre-Transfer: ")[-1].split()[0]) * 1000)
                    starttransfer_times.append(float(output.split("TTFB: ")[-1].split()[0]) * 1000)
                    total_time = float(output.split("Time Total: ")[-1].split()[0]) * 1000
                    total_times.append(total_time)
                    download_size = int(output.split("Download Size: ")[-1].split()[0])
                    total_downloaded_bytes += download_size
                else:
                    failed_requests += 1
            else:
                failed_requests += 1

    end_time = time.time()
    total_duration = end_time - start_time
    total_downloaded_mb = total_downloaded_bytes / (1024 * 1024)
    

    # Adicionando cálculo de P90 e P95
    def print_statistics(name, times):
        if times:
            p90 = round(statistics.quantiles(times, n=10)[8], 1)  # P90
            p95 = round(statistics.quantiles(times, n=20)[18], 1)  # P95
            print(f"{name}:    min: {min(times):.1f}  mean: {statistics.mean(times):.1f}  stdev: {statistics.stdev(times):.1f}  median: {statistics.median(times):.1f}  max: {max(times):.1f}  P90: {p90}  P95: {p95}")
        else:
            print(f"{name}: No data available.")

    print(f"\nProtocol: {protocol}")
    print(f"Method:              {method}")
    print(f"Concurrency Level:   {concurrency}")
    print(f"Time taken for tests: {total_duration:.3f} seconds")
    print(f"Complete requests:   {num_requests}")
    print(f"Failed requests:     {failed_requests}")
    print(f"Total transferred:   {total_downloaded_mb:.2f} MB")
    print(f"Requests per second: {num_requests / total_duration:.2f} [#/sec] (mean)")

    if total_times:
        print(f"\nTime per request (mean):    {statistics.mean(total_times):.3f} ms")
        print(f"Time per request (P90):     {statistics.quantiles(total_times, n=10)[8]:.3f} ms")
        print(f"Time per request (P95):     {statistics.quantiles(total_times, n=20)[18]:.3f} ms")
        print(f"Time per request (mean/concurrency): {statistics.mean(total_times) / concurrency:.3f} ms (mean across all concurrent requests)")

    if dns_times:
        print_statistics("DNS Lookup", dns_times)
        print_statistics("TCP Connect", connect_times)
        print_statistics("SSL Handshake", ssl_times)
        print_statistics("Pre-Transfer", pretransfer_times)
        print_statistics("TTFB", starttransfer_times)
        print_statistics("Total", total_times)
    
    if qod == 1 and id_session and access_token:
        close_qod_session(id_session, access_token)

def close_qod_session(id_session, access_token):
    print("Closing QoD Session..")
    url = f"https://api.br-pro.baikalplatform.com/qod/v0/sessions/{id_session}"
    payload = ""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    response = requests.delete(url, data=payload, headers=headers)
    print("QoD Session closed..")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performance testing with different HTTP versions")
    parser.add_argument('--http1_1', action='store_true', help='Test with HTTP/1.1')
    parser.add_argument('--http2', action='store_true', help='Test with HTTP/2')
    parser.add_argument('--http3', action='store_true', help='Test with HTTP/3')
    parser.add_argument('--method', type=str, default='POST', help='HTTP method to use (default: POST)')
    parser.add_argument('--data', type=str, help='Data to send with POST request')
    parser.add_argument('--headers', type=str, nargs='*', help='Custom headers to send with the request (e.g., "Authorization: Bearer TOKEN")')
    parser.add_argument('--cookie', type=str, help='Cookie to send with the request')
    parser.add_argument('--n', type=int, default=1000, help='Number of requests (default: 1000)')
    parser.add_argument('--c', type=int, default=10, help='Concurrency level (default: 10)')
    parser.add_argument('--url', type=str, default='https://mobilets8aws.rdhi.com.br/router-app/router/mobile', help='URL to test (default: https://mobilets8aws.rdhi.com.br/router-app/router/mobile)')
    parser.add_argument('--gzip', action='store_true', help='Enable gzip compression for requests')
    parser.add_argument('--gzip_itau', action='store_true', help='Enable custom Itau gzip compression header (X-Accept: itau-compress-response)')
    parser.add_argument('--k', action='store_true', help='Allow insecure server connections when using SSL')
    parser.add_argument('--msisdn', type=str, help='MSISDN for QoD session')
    parser.add_argument('--qod', type=int, default=0, help='QoD flag (0 or 1)')

    args = parser.parse_args()

    protocols = []
    if args.http1_1:
        protocols.append("http1_1")
    if args.http2:
        protocols.append("http2")
    if args.http3:
        protocols.append("http3")

    headers = [
        'Content-Type: application/json',
        'User-Agent: os=ios;os_version=17.4.1;device_model=iPhone15.4;device_maker=Apple;device_type=smartphone;app_id=com.itau.iphone.varejo;app_version=7.064.1;sdkv=4.0.6;cda=T;AppItauSmartPF',
        'ajaxRequest: true',
        'cdata: false',
        'pre-login: pre-login'
    ]

    post_data = json.dumps({
        "query": [],
        "path": [],
        "header": [
            {"key": "idMobileStrong", "value": "WFWEOIFJWEOIFJWEOIFJOWEJFOIWE"},
            {"key": "idMobileWeak", "value": "WFWEOIFJWEOIFJWEOIFJOWEIJFOIWE"},
            {"key": "idMobileOld", "value": "WFWEOIFJWEOIFJWEOIFJOWEIJFOIWE"},
            {"key": "_remoteBundleHash", "value": "975a619be74aec22994a4e9d80b07daf975a2afu"}
        ],
        "body": {
            "tipoLogon": "51",
            "usuario": {
                "agencia": "1500",
                "conta": "01004",
                "dac": "0"
            }
        },
        "method": "POST"
    })

    cookie = "JSESSIONID=0000D3rk252iJsK9PbxanVBrjnM%3A21751305-b6e0-41b5-b306-e57e4aef2fd2"
    
    if not protocols:
        print("Error: At least one protocol must be specified (--http1_1, --http2, --http3).")
    else:
        for protocol in protocols:
            print(f"\nTesting with protocol: {protocol}")
            run_test(args.url, protocol, args.method.upper(), post_data, headers, cookie, args.n, args.c, args.gzip, args.gzip_itau, args.k, args.msisdn, args.qod)
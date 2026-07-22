import socket
import concurrent.futures
import ssl
import time


class Scanner:

    def __init__(self, rate=100, timeout=5, verbose=False):
        self.rate = rate
        self.timeout = timeout
        self.verbose = verbose

    def scan(self, target):
        result = {
            "host": target.host,
            "port": target.port,
            "protocol": target.protocol,
            "status": "closed",
            "service": None,
            "version": None,
            "banner": None,
            "tls": False,
        }

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((target.host, target.port))
            result["status"] = "open"

            service = self._detect_service(target.port)
            result["service"] = service

            banner = self._grab_banner(sock, target.port)
            if banner:
                result["banner"] = banner[:200]

            if target.port == 443 or target.port == 8443:
                tls_info = self._check_tls(target.host, target.port)
                result["tls"] = True
                result["tls_info"] = tls_info

        except socket.timeout:
            result["status"] = "filtered"
        except ConnectionRefusedError:
            result["status"] = "closed"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        finally:
            sock.close()

        return result

    def scan_many(self, targets, max_workers=50):
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan, t): t for t in targets}
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        "host": target.host,
                        "port": target.port,
                        "status": "error",
                        "error": str(e),
                    })
                if self.verbose:
                    status = result.get("status", "unknown")
                    service = result.get("service", "")
                    print(f"  {target.host}:{target.port} - {status} {service}")
                time.sleep(1.0 / self.rate)
        return results

    def _detect_service(self, port):
        common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 2049: "nfs",
            3306: "mysql", 3389: "rdp", 5432: "postgresql",
            5900: "vnc", 6379: "redis", 8080: "http-proxy",
            8443: "https-alt", 27017: "mongodb",
        }
        return common_ports.get(port, "unknown")

    def _grab_banner(self, sock, port):
        try:
            if port == 443 or port == 8443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssock = context.wrap_socket(sock, server_hostname="localhost")
                return ssock.version()
            sock.send(b"\r\n")
            banner = sock.recv(1024)
            return banner.decode("utf-8", errors="ignore").strip()
        except Exception:
            return None

    def _check_tls(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                    return {
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "subject": cert_obj.subject.rfc4514_string(),
                        "issuer": cert_obj.issuer.rfc4514_string(),
                        "expiry": str(cert_obj.not_valid_after),
                    }
        except Exception:
            return None

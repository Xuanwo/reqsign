#!/usr/bin/env python3
"""
Mock OAuth2 server for Azure AD authentication testing.
This simulates the Azure AD token endpoint for testing purposes.
"""

import json
import time
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

# Mock OAuth2 token response
def create_mock_token(client_id, tenant_id):
    # Create a mock JWT token
    header = {
        "typ": "JWT",
        "alg": "RS256",
        "x5t": "Mr5-AUibfBii7Nd1jBebaxboXW0",
        "kid": "Mr5-AUibfBii7Nd1jBebaxboXW0"
    }
    
    payload = {
        "aud": "https://storage.azure.com/",
        "iss": f"https://sts.windows.net/{tenant_id}/",
        "iat": int(time.time()),
        "nbf": int(time.time()),
        "exp": int(time.time()) + 3600,
        "aio": "E2NgYKi7sst/bW/tL/Y7+AA=",
        "appid": client_id,
        "appidacr": "1",
        "idp": f"https://sts.windows.net/{tenant_id}/",
        "oid": "12345678-1234-1234-1234-123456789012",
        "rh": "0.ARoAv4j-5gpDiUGGpAA3XEvFcmQkAAAAAAAAwAAAAAAAAAA.",
        "sub": "12345678-1234-1234-1234-123456789012",
        "tid": tenant_id,
        "uti": "12345678-1234-1234-1234-123456789012",
        "ver": "1.0"
    }
    
    # Create a mock JWT (not cryptographically valid, just for testing)
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    signature = "mock_signature"
    
    return f"{header_b64}.{payload_b64}.{signature}"


class OAuthMockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        path_parts = self.path.strip('/').split('/')
        
        # Expected path format: /{tenant_id}/oauth2/v2.0/token or /{tenant_id}/oauth2/token
        if len(path_parts) < 3 or path_parts[1] != 'oauth2':
            self.send_error(404, "Not Found")
            return
        
        tenant_id = path_parts[0]
        
        # Read request body
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)
        
        # Validate grant type
        grant_type = params.get('grant_type', [''])[0]
        
        if grant_type == 'client_credentials':
            # Service principal with client secret
            client_id = params.get('client_id', [''])[0]
            client_secret = params.get('client_secret', [''])[0]
            scope = params.get('scope', ['https://storage.azure.com/.default'])[0]
            
            if not client_id or not client_secret:
                self.send_error(400, "client_id and client_secret are required")
                return
            
            # Create mock response
            token = create_mock_token(client_id, tenant_id)
            response = {
                "token_type": "Bearer",
                "expires_in": 3599,
                "ext_expires_in": 3599,
                "access_token": token
            }
            
        elif grant_type == 'urn:ietf:params:oauth:grant-type:jwt-bearer':
            # Federated token (workload identity)
            client_id = params.get('client_id', [''])[0]
            client_assertion = params.get('client_assertion', [''])[0]
            client_assertion_type = params.get('client_assertion_type', [''])[0]
            scope = params.get('scope', ['https://storage.azure.com/.default'])[0]
            
            if not client_id or not client_assertion:
                self.send_error(400, "client_id and client_assertion are required")
                return
            
            # Create mock response
            token = create_mock_token(client_id, tenant_id)
            response = {
                "token_type": "Bearer",
                "expires_in": 3599,
                "ext_expires_in": 3599,
                "access_token": token
            }
            
        else:
            self.send_error(400, f"Unsupported grant_type: {grant_type}")
            return
        
        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        # Override to print logs
        print(f"[OAuth Mock] {format % args}")


def run_server(port=8081):
    server_address = ('', port)
    httpd = HTTPServer(server_address, OAuthMockHandler)
    print(f"OAuth Mock Server running on port {port}")
    print("Set AZURE_AUTHORITY_HOST=http://localhost:8081 to use this mock server")
    httpd.serve_forever()


if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    run_server(port)
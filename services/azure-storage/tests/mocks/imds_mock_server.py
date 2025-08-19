#!/usr/bin/env python3
"""
Mock IMDS (Instance Metadata Service) server for Azure Storage testing.
This simulates the Azure IMDS endpoint for testing purposes.
"""

import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Mock token response
MOCK_TOKEN = {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL3N0b3JhZ2UuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L3Rlc3QtdGVuYW50LWlkLyIsImlhdCI6MTY5ODc2ODAwMCwibmJmIjoxNjk4NzY4MDAwLCJleHAiOjE2OTg4NTQ0MDAsImFpbyI6IkUyTmdZS2k3c3N0L2JXL3RML1k3K0FBPSIsImFwcGlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5MDEyIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvdGVzdC10ZW5hbnQtaWQvIiwib2lkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5MDEyIiwicmgiOiIwLkFSb0F2NGotNWdwRGlVR0dwQUEzWEV2RmNtUWtBQUFBQUFBQUF3QUFBQUFBQUFBQS4iLCJzdWIiOiIxMjM0NTY3OC0xMjM0LTEyMzQtMTIzNC0xMjM0NTY3ODkwMTIiLCJ0aWQiOiJ0ZXN0LXRlbmFudC1pZCIsInV0aSI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTAxMiIsInZlciI6IjEuMCIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL3Rlc3Qtc3ViLWlkL3Jlc291cmNlZ3JvdXBzL3Rlc3QtcmcvcHJvdmlkZXJzL01pY3Jvc29mdC5NYW5hZ2VkSWRlbnRpdHkvdXNlckFzc2lnbmVkSWRlbnRpdGllcy90ZXN0LWlkZW50aXR5In0.mock_signature",
    "client_id": "12345678-1234-1234-1234-123456789012",
    "expires_in": "86400",
    "expires_on": str(int(time.time()) + 86400),
    "ext_expires_in": "86400",
    "not_before": str(int(time.time())),
    "resource": "https://storage.azure.com/",
    "token_type": "Bearer"
}


class IMDSMockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        # Check for required Metadata header
        if self.headers.get('Metadata') != 'true':
            self.send_error(400, "Metadata header must be 'true'")
            return
        
        if path == '/metadata/identity/oauth2/token':
            # Validate required parameters
            api_version = query_params.get('api-version', [''])[0]
            resource = query_params.get('resource', [''])[0]
            
            if not api_version:
                self.send_error(400, "api-version is required")
                return
            
            if not resource:
                self.send_error(400, "resource is required")
                return
            
            # Optional parameters
            client_id = query_params.get('client_id', [''])[0]
            object_id = query_params.get('object_id', [''])[0]
            msi_res_id = query_params.get('msi_res_id', [''])[0]
            
            # Send mock token response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = MOCK_TOKEN.copy()
            response['resource'] = resource
            if client_id:
                response['client_id'] = client_id
            
            self.wfile.write(json.dumps(response).encode())
        
        elif path == '/metadata/instance':
            # Instance metadata endpoint
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            instance_data = {
                "compute": {
                    "azEnvironment": "AzurePublicCloud",
                    "customData": "",
                    "location": "eastus",
                    "name": "test-vm",
                    "offer": "0001-com-ubuntu-server-focal",
                    "osType": "Linux",
                    "placementGroupId": "",
                    "plan": {
                        "name": "",
                        "product": "",
                        "publisher": ""
                    },
                    "platformFaultDomain": "0",
                    "platformUpdateDomain": "0",
                    "provider": "Microsoft.Compute",
                    "publicKeys": [],
                    "publisher": "canonical",
                    "resourceGroupName": "test-rg",
                    "resourceId": "/subscriptions/test-sub-id/resourceGroups/test-rg/providers/Microsoft.Compute/virtualMachines/test-vm",
                    "sku": "20_04-lts",
                    "storageProfile": {
                        "dataDisks": [],
                        "imageReference": {
                            "id": "",
                            "offer": "0001-com-ubuntu-server-focal",
                            "publisher": "canonical",
                            "sku": "20_04-lts",
                            "version": "latest"
                        },
                        "osDisk": {
                            "caching": "ReadWrite",
                            "createOption": "FromImage",
                            "diskSizeGB": "30",
                            "encryptionSettings": {
                                "enabled": "false"
                            },
                            "image": {
                                "uri": ""
                            },
                            "managedDisk": {
                                "id": "/subscriptions/test-sub-id/resourceGroups/test-rg/providers/Microsoft.Compute/disks/test-vm-osdisk",
                                "storageAccountType": "Premium_LRS"
                            },
                            "name": "test-vm-osdisk",
                            "osType": "Linux",
                            "vhd": {
                                "uri": ""
                            },
                            "writeAcceleratorEnabled": "false"
                        }
                    },
                    "subscriptionId": "test-sub-id",
                    "tags": "",
                    "version": "20.04.202201131",
                    "vmId": "12345678-1234-1234-1234-123456789012",
                    "vmScaleSetName": "",
                    "vmSize": "Standard_B2s",
                    "zone": "1"
                },
                "network": {
                    "interface": []
                }
            }
            
            self.wfile.write(json.dumps(instance_data).encode())
        
        else:
            self.send_error(404, "Not Found")
    
    def log_message(self, format, *args):
        # Override to print logs
        print(f"[IMDS Mock] {format % args}")


def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, IMDSMockHandler)
    print(f"IMDS Mock Server running on port {port}")
    print("Set AZURE_IMDS_ENDPOINT=http://localhost:8080 to use this mock server")
    httpd.serve_forever()


if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
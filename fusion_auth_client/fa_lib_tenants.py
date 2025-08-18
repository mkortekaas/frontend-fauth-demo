#####################################################################################################################################################
import sys

class Tenants:
    def __init__(self, client, tenant_id=None):
        self.client = client
        self.cache = {}
        self.tenant_id = None

        if tenant_id:
            is_valid_uuid, uuid_obj = self.client.__is_valid_uuid__(tenant_id)
            if is_valid_uuid:
                # Normalize to string for consistent header usage
                self.tenant_id = str(uuid_obj)
            else:
                # Not a valid UUID, treat as tenant name
                self.tenant_id = self.get_id_by_name(tenant_id)
        else:
            # Search for default tenant
            self.tenant_id = self.get_id_by_name("default")

        if self.tenant_id:
            self.client.headers['X-FusionAuth-TenantId'] = str(self.tenant_id)
        else:
            sys.exit(f"ERROR: Could not determine tenant ID unable to continue")

    def get_id_by_name(self, tenant_name):
        """Search for tenant by name and return its ID."""
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/tenant/search",
            method="POST",
            headers=self.client.headers,
            json={"search": {"name": tenant_name}}
        )
        if response:
            result = response.json()
            total_found = result.get('total', 0)
            tenants = result.get('tenants', [])
            
            if total_found == 0:
                return None
            elif total_found == 1:
                if tenant_name.lower() == tenants[0]['name'].lower():
                    return tenants[0]['id']
            else:
                # Print all found tenants for debugging
                for i, tenant in enumerate(tenants):
                    if tenant_name.lower() == tenant['name'].lower():
                        return tenant['id']
                    else:
                        print(f"  {i+1}. {tenant.get('name', 'Unknown')} (ID: {tenant.get('id', 'Unknown')}) {tenant_name}")
                return None
        else:
            return None

    def get_all_tenants(self):
        # if the header has the X-FusionAuth-TenantId, we need to remove it
        my_headers = self.client.headers.copy()
        if 'X-FusionAuth-TenantId' in self.client.headers:
            del my_headers['X-FusionAuth-TenantId']

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/tenant",
            headers=my_headers,
        )
        if response:
            return response.json()
        else:
            return None

    def get_tenant_id(self):
        return self.tenant_id
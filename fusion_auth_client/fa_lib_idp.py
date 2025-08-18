import json

#####################################################################################################################################################
class IdentityProviders:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def get_idp_id(self, idp_name):
        """
        Retrieve the ID of an identity provider by name.
        
        Args:
            idp_name (str): Name of the identity provider
            
        Returns:    
            str: Identity provider ID if found, None otherwise
        """
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/identity-provider/search",
            headers=self.client.headers,
            params={'name': idp_name}
        )
        if response:
            result = response.json()
            # print(json.dumps(result, indent=2))
            total_found = result.get('total', 0)
            idps = result.get('identityProviders', [])
            if total_found == 0:
                print('hi')
                return None
            elif total_found == 1:
                idp_id = idps[0]['id']
                return idp_id
            else:
                print(f"Error: {total_found} identity providers found for '{idp_name}' (expected exactly 1)")
                return None
        else:
            return None

    def get_idp_user_id(self, idp_name, email):
        """
        Retrieve the ID of an identity provider user by name and email.
        
        Args:
            idp_name (str): Name of the identity provider
            email (str): Email address of the user

        Returns:
            str: Identity provider user ID if found, None otherwise
        """
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/identity-provider/search",
            headers=self.client.headers,
            params={'name': idp_name}
        )
        if response:
            result = response.json()
            total_found = result.get('total', 0)
            idps = result.get('identityProviders', [])
            if total_found == 0:
                return None
            elif total_found == 1:
                idp_id = idps[0]['id']

                ## ok - we have a confirmed idp_id - now we need to find all users in all tenants and see if we can find the idp_user_id -- sadly this is a bit of a pain in the ass
                ## we need to get all tenants
                tenants = self.client.Tenants.get_all_tenants()
                if not tenants:
                    print("No tenants found")
                    return None
                for tenant in tenants.get('tenants', []):
                    my_headers = self.client.headers.copy()
                    my_headers['X-FusionAuth-TenantId'] = tenant['id']
                    user = self.client.Users.get(email, tenant_id=tenant['id'])
                    if not user:
                        print(f"No user found for tenant {tenant['name']}")
                        continue
                    else:
                        ## now that we are here - see if we can find the user for this tenant with this idp_id
                        idp_link_user = self.client.__api_call__(
                            f"{self.client.server_url}/api/identity-provider/link",
                            "GET",
                            200,
                            headers=my_headers,
                            params={"identityProviderId": idp_id,
                                    "userId": user['user']['id'], }
                        )
                        if idp_link_user:
                            if idp_link_user.json().get('identityProviderLinks'):
                                return idp_link_user.json().get('identityProviderLinks')[0]['identityProviderUserId']
                return None
            else:
                print(f"Error: {total_found} identity providers found for '{idp_name}' (expected exactly 1)")
                return None
        else:
            return None

    def link_idp_user(self, user_id, idp_id, idp_user_id, email_address):
        """
        Link a user to an identity provider.
        
        Args:   
            user_id (str): FusionAuth user ID
            idp_id (str): FusionAuth identity provider ID

        Returns:
            bool: True if successful, False otherwise
        """
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/identity-provider/link",
            method="POST",
            headers=self.client.headers,
            json={
                "identityProviderLink": {
                    "identityProviderId": idp_id,
                    "identityProviderUserId": idp_user_id,
                    "userId": user_id,
                    "displayName": email_address
                }
            }
        )
        if response:
            return response.json()
        else:
            return None
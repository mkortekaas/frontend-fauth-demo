#####################################################################################################################################################
import json

class Applications:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def get(self, application_name, tenant_id=None):
        """
        Retrieve the application details for a given application name.
        
        Args:
            application_name (str): Name of the application to retrieve

        Returns:
            str: Application if found, None otherwise
        """
        application = None
        if application_name in self.cache:
            return self.cache[application_name]

        headers = self.client.headers.copy()
        if tenant_id:
            headers['X-FusionAuth-TenantId'] = tenant_id

        # see if the application name is a uuid 
        is_valid_uuid, uuid_obj = self.client.__is_valid_uuid__(application_name)
        if is_valid_uuid:
            # get the application by uuid
            response = self.client.__api_call__(
                url=f"{self.client.server_url}/api/application/{application_name}",
                method="GET",
                headers=headers
            )
            if response:
                result = response.json()
                application = result.get('application', None)
        else:    
            response = self.client.__api_call__(
                url=f"{self.client.server_url}/api/application/search", 
                method="POST",
                headers=headers,
                json={"search": {"name": application_name}}
            )
        
            if response:
                result = response.json()
                total_found = result.get('total', 0)
                applications = result.get('applications', [])
                if total_found == 1:
                    application = applications[0]
                else:
                    ## Search returns all applications with the name - we need to find the exact match
                    for app in applications:
                        if app['name'].lower() == application_name.lower():
                            application = app
                            break
                    if not application:
                        print(f"Error: {total_found} applications found for '{application_name}' (expected exactly 1)")
                        return None
        
        return application

    def get_id(self, application_name, tenant_id=None, environment=None):
        """
        Retrieve the application ID for a given application name.
        
        Args:
            application_name (str): Name of the application to retrieve

        Returns:
            str: Application ID if found, None otherwise
        """
        if environment:
            ## YOU WILL WANT TO PUT YOUR OWN STRINGS/TENANTS HERE FOR EACH ENVIRONMENT YOU HAVE - this is shortcut
            if environment == "foo" and application_name == "bar":
                return "UUID"
            else:
                print(f"Application ID not found for {application_name} in {environment}")
                return None

        application = self.get(application_name, tenant_id)
        if application:
            return application['id']
        else:
            return None

    def get_all_users(self, application_id):
        """
        Retrieve all users for a given application name.
        
        Args:
            application_id (str): ID of the application to retrieve users for
            
        Returns:
            list: List of users if found, None otherwise
        """
        query = {
            "bool": {
                "must": [{
                    "nested": {
                        "path": "registrations",
                        "query": {
                            "bool": {
                                "must": [
                                    {
                                        "match": {
                                            "registrations.applicationId": application_id
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }]
            }
        }
        
        all_users = []
        start_row = 0
        page_size = 100
        
        while True:
            searchCriteria = {
                "search": {
                    "query": json.dumps(query),  ## if we don't use json.dumps() the formatting is off for what FA requires
                    "startRow" : start_row,
                    "numberOfResults" : page_size,
                }
            }
            response = self.client.__api_call__(
                url=f"{self.client.server_url}/api/user/search",
                method="POST",
                headers=self.client.headers,
                json=searchCriteria
            )
            if not response:
                return None
            
            result = response.json()
            users = result.get('users', [])
            total = result.get('total', 0)
            
            all_users.extend(users)
            
            # Check if we've retrieved all users
            if len(all_users) >= total:
                break
            
            # Move to next page
            start_row += page_size
        
        return all_users


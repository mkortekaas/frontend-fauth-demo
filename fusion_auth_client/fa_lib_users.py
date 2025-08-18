#####################################################################################################################################################
class Users:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def __cache_set__(self, user_data):
        return self.client.__cache_set__(self.cache, user_data['user']['id'], user_data)

    def __cache_get__(self, cache_key):
        return self.client.__cache_get__(self.cache, cache_key)

    def create(self, email, password, first_name, last_name, application_id=None, entity_id=None):
        """
        Create a user.
        
        Args:
            email (str): User's email address
            password (str): User's password
            first_name (str): User's first name
            last_name (str): User's last name
        """
        if self.__cache_get__(email):
            return None

        user_request = {
            'sendSetPasswordEmail': False,
            'skipVerification': True,
            'user': {
                'email': email,
                'password': password,
                'firstName': first_name,
                'lastName': last_name,
            }
        }
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user",
            method="POST",
            headers=self.client.headers,
            json=user_request
        )
        if response:
            my_response = self.__cache_set__(response.json())

            if application_id:
                self.register_application(my_response['user']['id'], application_id)

            if entity_id:
                self.client.Entities.grant(entity_id, my_response['user']['id'], ['admin'])

            return my_response
        else:
            return None

    def search(self, application_id=None, query_string=None, start=0, number_of_results=100, tenant_id=None, entity_id=None, expand_registrations=False):
        """
        Search users. If application_id is provided, filters users registered to that application.

        Args:
            application_id (str, optional): FusionAuth application ID to filter by registration
            query_string (str, optional): Additional Elasticsearch query string
            start (int): Starting row for pagination
            number_of_results (int): Number of results to return
            tenant_id (str, optional): Override tenant for the request

        Returns:
            dict: Search result containing 'users' and 'total' when successful, None otherwise
        """
        parts = []
        if tenant_id:
            my_headers = self.client.headers.copy()
            my_headers['X-FusionAuth-TenantId'] = str(tenant_id)
        else:
            my_headers = self.client.headers
        
        if application_id:
            parts.append(f'registrations.applicationId:"{application_id}"')
        # if entity_id:
        #     parts.append(f'entityId:"{entity_id}"')
        if query_string:
            parts.append(f'({query_string})')
        final_query =' AND '.join(parts) if parts else '*'

        search_request = {
            "search": {
                "tenantId": self.client.tenant_id,
                "queryString": final_query,
                "startRow": start,
                "numberOfResults": number_of_results
            }
        }

        response = self.client.__api_search__(
            url=f"{self.client.server_url}/api/user/search",
            method="POST",
            headers=my_headers,
            json=search_request
        )

        if response:
            # Parse once, mutate, return the same object so caller sees adjustments
            data = response.json()
            if expand_registrations:
                for user in data.get('users', []) or []:
                    registrations = user.get('registrations') or []
                    for registration in registrations:
                        application_id = registration.get('applicationId')
                        if not application_id:
                            continue
                        application = self.client.Applications.get(application_id)
                        if application and isinstance(application, dict):
                            name = application.get('name')
                            if name:
                                registration['applicationId'] = name
            return data
        else:
            return None

    def delete(self, user_id):
        """
        Delete a user by ID.
        
        Args:
            user_id (str): FusionAuth user ID
            debug (bool): Enable debug output for this request
        """
        url = f"{self.client.server_url}/api/user/{user_id}"
        params = {'hardDelete': 'true'}
            
        if self.client.verbose:
            print(f"DEBUG - DELETE Request:")
            print(f"  URL: {url}")
            print(f"  Headers: {self.headers}")
            print(f"  Params: {params}")
            print("-" * 50)

        response = self.client.__api_call__(
            url=url,
            method="DELETE",
            headers=self.client.headers,
            params=params
        )
        if response:
            return True
        else:
            return False

    def get(self, id, tenant_id=None):
        """
        Retrieve complete user information by email.
        
        Args:
            email (str): User's email address
            
        Returns:
            dict: User data if found, None otherwise
        """
        is_valid_uuid, uuid_obj = self.client.__is_valid_uuid__(id)
        if is_valid_uuid:
            params = {'userId': id}
        else:
            params = {'email': id}

        if tenant_id:
            my_headers = self.client.headers.copy()
            my_headers['X-FusionAuth-TenantId'] = tenant_id
        else:
            my_headers = self.client.headers

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user",
            headers=my_headers,
            params=params
            )
            
        if response:
            return response.json()
        else:
            return None

    def get_id(self, email):
        """
        Retrieve the user ID for a given email.
        
        Args:
            email (str): User's email address
            
        Returns:
            str: User ID if found, None otherwise
        """
        user = self.get(email)
        if user:
            return user['user']['id']
        else:
            return None

    def get_grants(self, user_id):
        """
        Retrieve all entity grants for a given user ID.
        
        Args:
            user_id (str): FusionAuth user ID
            
        Returns:
            dict: Grants data if successful, None otherwise
        """
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/entity/grant/search",
            headers=self.client.headers,
            params={'userId': user_id}
        )
        if response:
            return response.json()
        else:
            return None

    def register_application(self, user_id, application_id, roles=None):
        """
        Register a user to an application.
        
        Args:
            application_id (str): FusionAuth application ID
            user_id (str): FusionAuth user ID
            roles (list, optional): List of roles to assign to the user

        Returns:
            dict: Registration data if successful, None otherwise
        """
        registration_data = {
            "applicationId": application_id
        }
        if roles:
            registration_data['roles'] = roles

        request_payload = {
            "registration": registration_data
        }

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user/registration/{user_id}",
            method="POST",
            headers=self.client.headers,
            json=request_payload
            )
        if response:
            return response.json()
        else:
            return None

    def set_application_roles(self, user_id, application_id, roles):
        """
        Set the roles for a user in an application.
        
        Args:
            user_id (str): FusionAuth user ID
            application_id (str): FusionAuth application ID
            roles (list): List of roles to set for the user

        Returns:
            dict: Registration data if successful, None otherwise
        """
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user/registration/{user_id}/{application_id}",
            headers=self.client.headers,
            )
        if response:
            current_registration = response.json()
        else:
            return None

        current_roles = current_registration['registration']['roles']
        if roles:
            current_roles.extend(roles)
        else:
            current_roles = roles

        request_payload = {
            "registration": {
                "roles": current_roles
            }
        }

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user/registration/{user_id}/{application_id}",
            method="PATCH",
            headers=self.client.headers,
            json=request_payload
        )
        if response:
            return response.json()
        else:
            return None

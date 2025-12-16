import string
import secrets

#####################################################################################################################################################
class Users:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def __cache_set__(self, user_data):
        return self.client.__cache_set__(self.cache, user_data['user']['id'], user_data)

    def __cache_get__(self, cache_key):
        return self.client.__cache_get__(self.cache, cache_key)

    def create(self, email, password=None, first_name=None, last_name=None, application_id=None, entity_id=None, tenant_id=None):
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

        # set base
        user_request = {
            'sendSetPasswordIdentityType': "doNotSend",
            # 'skipVerification': True,
            'user': {
                'email': email,
                'username': email,
                'firstName': first_name,
                'lastName': last_name,
            }
        }
        if password is None:
            idp_domains = self.client.IdentityProviders.get_all_idp_domains()
            if idp_domains:
                is_idp = False
                for domain in idp_domains:
                    if domain.endswith(email.split('@')[1]):
                        # add password if the domain is a valid idp domain 
                        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
                        password = ''.join(secrets.choice(alphabet) for i in range(16))
                        print(f"FAUTH: USER: {email} - initial password: {password}")
                        user_request['skipVerification'] = True
                        user_request['user']['password'] = password
                        is_idp = True
                        break
                if not is_idp:
                    # new user that has no initial password and needs to be created and emailed
                    ## TODO: DEBUG this - api ref is here: https://fusionauth.io/docs/apis/users
                    ##   - I think this uses the template for the tenant ???
                    user_request['sendSetPasswordIdentityType'] = 'email'
        else:
            # we were given an initial password to use
            user_request['user']['password'] = password

        my_headers = self.client.__get_headers__(tenant_id)

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user",
            method="POST",
            headers=my_headers,
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
        my_headers = self.client.__get_headers__(tenant_id)
        parts = []
        
        if application_id:
            parts.append(f'registrations.applicationId:"{application_id}"')
        # if entity_id:
        #     parts.append(f'entityId:"{entity_id}"')
        if query_string:
            parts.append(f'({query_string})')
        final_query =' AND '.join(parts) if parts else '*'

        search_request = {
            "search": {
                "tenantId": tenant_id if tenant_id else self.client.tenant_id,
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

    def delete(self, user_id, lock=False, tenant_id=None):
        """
        Delete a user by ID.
        
        Args:
            user_id (str): FusionAuth user ID
            debug (bool): Enable debug output for this request
        """
        my_headers = self.client.__get_headers__(tenant_id)
        url = f"{self.client.server_url}/api/user/{user_id}"
        if lock == False:
            params = {'hardDelete': 'true'}
        else:
            params = {}
            
        if self.client.verbose:
            print(f"DEBUG - DELETE Request:")
            print(f"  URL: {url}")
            print(f"  Headers: {self.client.headers}")
            print(f"  Params: {params}")
            print("-" * 50)

        response = self.client.__api_call__(
            url=url,
            method="DELETE",
            headers=my_headers,
            params=params
        )
        if response and response.status_code == 200:
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
        my_headers = self.client.__get_headers__(tenant_id)
        is_valid_uuid, uuid_obj = self.client.__is_valid_uuid__(id)
        if is_valid_uuid:
            params = {'userId': id}
        else:
            params = {'email': id}

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user",
            headers=my_headers,
            params=params
            )
            
        if response:
            return response.json()
        else:
            return None

    def get_id(self, email, tenant_id=None):
        """
        Retrieve the user ID for a given email.
        
        Args:
            email (str): User's email address
            
        Returns:
            str: User ID if found, None otherwise
        """
        user = self.get(email, tenant_id)
        if user:
            return user['user']['id']
        else:
            return None

    def get_grants(self, user_id, tenant_id=None):
        """
        Retrieve all entity grants for a given user ID.
        
        Args:
            user_id (str): FusionAuth user ID
            
        Returns:
            dict: Grants data if successful, None otherwise
        """
        my_headers = self.client.__get_headers__(tenant_id)
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/entity/grant/search",
            headers=my_headers,
            params={'userId': user_id}
        )
        if response:
            return response.json()
        else:
            return None

    def app_is_registered(self, user_id, application_id, tenant_id=None):
        """
        Check if a user is registered to an application.
        """
        my_headers = self.client.__get_headers__(tenant_id)
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user/registration/{user_id}/{application_id}",
            headers=my_headers,
        )
        if response:
            return response.json()
        else:
            return None

    def deregister_application(self, user_id, application_id, tenant_id=None):
        """
        Deregister a user from an application.
        """
        my_headers = self.client.__get_headers__(tenant_id)

        # verify application_id is valid in this tenant
        if not (application_uuid := self.client.Applications.get_id(application_id)):
            raise ValueError(f"Application {application_id} not found in tenant {tenant_id}")

        # verify user_id is valid in this tenant
        if not (user_uuid := self.get_id(user_id)):
            user_new = self.create(user_id)
            if not user_new:
                raise ValueError(f"Failed to create user {user_id} in tenant {tenant_id}")
            user_uuid = user_new['user']['id']

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user/registration/{user_uuid}/{application_uuid}",
            method="DELETE",
            headers=my_headers,
        )
        if response and response.status_code == 200:
            return True
        else:
            return False

    def register_application(self, user_id, application_id, roles=None, tenant_id=None):
        """
        Register a user to an application.
        
        Args:
            application_id (str): FusionAuth application ID
            user_id (str): FusionAuth user ID
            roles (list, optional): List of roles to assign to the user

        Returns:
            dict: Registration data if successful, None otherwise
        """
        if tenant_id is None:
            tenant_id = self.client.tenant_id
        my_headers = self.client.__get_headers__(tenant_id)

        # verify application_id is valid in this tenant
        if not (application_uuid := self.client.Applications.get_id(application_id)):
            raise ValueError(f"Application {application_id} not found in tenant {tenant_id}")

        # verify user_id is valid in this tenant
        if not (user_uuid := self.get_id(user_id)):
            user_new = self.create(user_id)
            if not user_new:
                raise ValueError(f"Failed to create user {user_id} in tenant {tenant_id}")
            user_uuid = user_new['user']['id']

        # verify if user is already registered to the application
        if (app_reg := self.app_is_registered(user_uuid, application_uuid)):
            return app_reg

        registration_data = {
            "applicationId": application_uuid,
            "username": user_id,
        }
        if roles:
            registration_data['roles'] = list(roles) if isinstance(roles, set) else roles

        request_payload = {
            "registration": registration_data
        }

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user/registration/{user_uuid}",
            method="POST",
            headers=my_headers,
            json=request_payload
            )
        if response:
            return response.json()
        else:
            return None

    def set_application_roles(self, user_id, application_id, roles, tenant_id=None):
        """
        Set the roles for a user in an application.
        
        Args:
            user_id (str): FusionAuth user ID
            application_id (str): FusionAuth application ID
            roles (list): List of roles to set for the user

        Returns:
            dict: Registration data if successful, None otherwise
        """
        user_uuid = self.get_id(user_id)
        my_headers = self.client.__get_headers__(tenant_id)
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user/registration/{user_uuid}/{application_id}",
            headers=my_headers,
            )
        if response:
            current_registration = response.json()
        else:
            return None

        # Convert roles to list if it's a set
        roles_list = list(roles) if isinstance(roles, set) else roles

        # Use PUT with the full registration object to replace roles completely
        # Update the current registration with the new roles
        current_registration['registration']['roles'] = roles_list
        
        request_payload = current_registration

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/user/registration/{user_uuid}/{application_id}",
            method="PUT",
            headers=my_headers,
            json=request_payload
        )
        if response:
            return response.json()
        else:
            return None

import json

#####################################################################################################################################################
class Entities:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def get(self, entity_name):
        """
        Retrieve the details of an entity by name.
        
        Args:
            entity_name (str): Name of the entity to retrieve
            
        Returns:
            dict: Entity data if found, None otherwise
        """
        search_request = {
            "search": {
                "queryString": f'name:"{entity_name}"'
            }
        }

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/entity/search",
            method="POST",
            json=search_request
        )

        if response:
            return response.json()
        else:
            return None

    def get_id(self, entity_name):
        """
        Retrieve the ID of an entity by name.
        """
        entities = self.get(entity_name)
        if entities:
            return entities['entities'][0]['id']
        else:
            return None

    def search(self, query_string):
        """
        Search for entities.
        """
        search_request = {
            "search": {
                "queryString": query_string
            }
        }

        response = self.client.__api_search__(
            url=f"{self.client.server_url}/api/entity/search",
            method="POST",
            json=search_request
        )

        if response:
            return response.json()
        else:
            return None
             
    def get_user_grants(self, entity_id, user_id):
        """
        Retrieve all entity grants for a given user ID.
        
        Args:
            entity_id (str): FusionAuth entity ID
            user_id (str): FusionAuth user ID

        Returns:
            dict: Grants data if successful, None otherwise
        """
        response = self.client.__api_call__(
            f"{self.client.server_url}/api/entity/{entity_id}/grant?userId={user_id}",
        )
            
        if response:
            return response.json()
        else:
            return None
        
    def get_permission_id(self, entity_name, permission_name):
        """
        Retrieve the ID of a permission for a given entity and permission name.
        
        Args:
            entity_name (str): Name of the entity
            permission_name (str): Name of the permission

        Returns:
            str: Permission ID if found, None otherwise
        """
        entity = self.get(entity_name)
        if entity:
            print(json.dumps(entity, indent=2))
            print("="*50)
            for permission in entity['entity']['type']['permissions']:
                if permission.get('name') == permission_name:
                    return permission['id']
        return None

    def assign_to_user(self, user_id, permission_name, entity_id):
        """
        Assign an entity to a user.
        
        Args:
            user_id (str): FusionAuth user ID
            permission_name (str): Name of the permission to assign
            entity_id (str): ID of the entity to assign
            
        Returns:
            bool: True if successful, False otherwise
        """
        ## note this replaces the permission set - so if you want to add to the set you need to get the current set and add to it
        json_data = {
            "grant": {
                "userId": user_id,
                "permissions": [
                    permission_name
                ]
            }
        }
        print(json.dumps(json_data, indent=2))
            
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/entity/{entity_id}/grant",
            method="POST",
            json=json_data
        )
            
        if response:
            return response.json()
        else:
            return None

    def get_users(self, entity_id):
        """
        Retrieve all users for a given entity ID.
        
        Args:
            entity_id (str): FusionAuth entity ID
            
        Returns:
            dict: Users data if successful, None otherwise  
        """
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/entity/{entity_id}/grant",
        )
            
        if response:
            return response.json()
        else:
            return None

    def grant(self, entity_id, user_id, permissions=None):
        """
        Grant an entity to a user.
        """
        json_data = {
            "grant": {
                "userId": user_id
            }
        }
        if permissions:
            # Convert string to list if needed
            if isinstance(permissions, str):
                json_data["grant"]["permissions"] = [permissions]
            else:
                json_data["grant"]["permissions"] = permissions

        # print(json.dumps(json_data, indent=2))
        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/entity/{entity_id}/grant",
            method="POST",
            json=json_data
        )
        if response.status_code == 200:
            return True
        else:
            return False

    def get_grants(self, user_id, entity_id=None):
        """
        Retrieve all grants for a given user ID.
        """
        if entity_id:
            url = f"{self.client.server_url}/api/entity/{entity_id}/grant?userId={user_id}"
        else:
            url = f"{self.client.server_url}/api/entity/grant/search?userId={user_id}"

        response = self.client.__api_call__( url=url, )
        if response:
            return response.json()
        else:
            return None

    def get_user_grants_by_entity(self, entity_id, expand_user_email=False):
        """
        Retrieve all users for a given entity ID.
        """

        ### this didn't work but should have??
        # search_request = {
        #     "search": {
        #         "entityId": entity_id,
        #     }
        # }
        # response = self.client.__api_search__(
        #     url=f"{self.client.server_url}/api/entity/grant/search",
        #     method="POST",
        #     json=search_request
        # )
        # if response:
        #     print(json.dumps(response.json(), indent=2))

        response = self.client.__api_call__(
            url=f"{self.client.server_url}/api/entity/{entity_id}/grant",
            # params = search_request,
            method="GET",
        )
        if response:
            # Store the response data so we can modify it
            response_data = response.json()           
            if expand_user_email:
                for grant in response_data['grants']:
                    user_details = self.client.Users.get(grant['userId'])
                    grant['userEmail'] = user_details['user']['email']
            return response_data
        else:
            return None
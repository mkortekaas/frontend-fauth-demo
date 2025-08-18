#####################################################################################################################################################
import json

class Applications:
    def __init__(self, client):
        self.client = client
        self.cache = {}

    def get(self, application_name):
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

        # see if the application name is a uuid 
        is_valid_uuid, uuid_obj = self.client.__is_valid_uuid__(application_name)
        if is_valid_uuid:
            # get the application by uuid
            response = self.client.__api_call__(
                url=f"{self.client.server_url}/api/application/{application_name}",
                method="GET",
                headers=self.client.headers
            )
            if response:
                result = response.json()
                application = result.get('application', None)
        else:    
            response = self.client.__api_call__(
                url=f"{self.client.server_url}/api/application/search", 
                method="POST",
                headers=self.client.headers,
                json={"search": {"name": application_name}}
            )
        
            if response:
                result = response.json()
                total_found = result.get('total', 0)
                applications = result.get('applications', [])
                if total_found == 1:
                    application = applications[0]
                else:
                    print(f"Error: {total_found} applications found for '{application_name}' (expected exactly 1)")
        
        return application

    def get_id(self, application_name):
        """
        Retrieve the application ID for a given application name.
        
        Args:
            application_name (str): Name of the application to retrieve

        Returns:
            str: Application ID if found, None otherwise
        """
        application = self.get(application_name)
        if application:
            return application['id']
        else:
            return None

    def get_all_users(self, application_name):
        """
        Retrieve all users for a given application name.
        
        Args:
            application_name (str): Name of the application to retrieve
        """
        # for some reason this query has to be manually crafted like this or you get a
        # json parsing error from the FA library???
        query = "{ \"bool\" : { \"must\" : [ [ { \"nested\" : { \"path\" : \"registrations\", \"query\" : { \"bool\" : { \"must\" : [ { \"match\" : { \"registrations.applicationId\" : \"" + os.environ.get('FUSIONA_APPID') + "\"} } ] } } } } ] ] } }"
        searchCriteria = {
            "search": {
                "query": query,
                "startRow" : 0,
                "numberOfResults" : 100,
            }
        }
        print("NEED TO IMPLEMENT THIS")

        # response = self.client.__api_call__(
        #     url=f"{self.client.server_url}/api/user/search",
        #     method="POST",
        #     headers=self.client.headers,
        #     json=searchCriteria
        # )


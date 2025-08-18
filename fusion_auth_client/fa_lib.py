"""
FusionAuth API library for user and entity grant operations.
Provides a class-based interface for interacting with FusionAuth's REST API.
https://fusionauth.io/docs/apis/
"""

import requests
import json
import uuid
from .fa_lib_tenants import Tenants
from .fa_lib_applications import Applications
from .fa_lib_users import Users
from .fa_lib_idp import IdentityProviders
from .fa_lib_entities import Entities

class fusion_auth_client:
    """FusionAuth API client for user and entity grant operations."""
    
    def __init__(self, server_url, api_key, tenant_id=None, verbose=False):
        """
        Initialize the FusionAuth client.
        
        Args:
            server_url (str): FusionAuth server URL (e.g., https://auth.example.com)
            api_key (str): FusionAuth API key
        """
        self.server_url = server_url.rstrip('/')  # Remove trailing slash if present
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
        self.verbose = verbose
        self.tenant_id = tenant_id

        # Initialize Tenants class -- uses tenant_id
        self.Tenants = Tenants(self, tenant_id)

        # Initialize sub-classes
        self.Users = Users(self)
        self.Applications = Applications(self)
        self.IdentityProviders = IdentityProviders(self)
        self.Entities = Entities(self)

    def __cache_set__(self, cache, cache_key, json_data):
        cache[cache_key] = json_data
        return json_data
        
    def __cache_get__(self, cache, cache_key):
        if cache_key in cache:
            return cache[cache_key]
        else:
            return None

    def __is_valid_uuid__(self, value):
        """
        Check if a value is a valid UUID (either as UUID object or string).
        
        Args:
            value: The value to check (can be UUID object, string, or anything else)
            
        Returns:
            tuple: (is_valid, uuid_object_or_none)
                - is_valid (bool): True if valid UUID, False otherwise
                - uuid_object_or_none: UUID object if valid, None if invalid
        """
        if isinstance(value, uuid.UUID):
            return True, value
        elif isinstance(value, str):
            try:
                parsed_uuid = uuid.UUID(value)
                return True, parsed_uuid
            except ValueError:
                return False, None
        else:
            return False, None

    def __api_call__(self, url, method="GET", retval=200, headers=None, params=None, json=None):
        if self.verbose:
            print(f"DEBUG: {method} {url} - {json}")
        if headers is None:
            headers = self.headers
        try:
            response = requests.request(method, url, headers=headers, params=params, json=json)
            if response.status_code == retval:
                return response
            else:
                print(f"WARNING: {method} {url} - {response.status_code} - {response.text}")
                return None
        except requests.RequestException as e:
            print(f"ERROR: {url} - {method} - {e}")
            return None

    def __api_search__(self, url, method="POST", retval=200, headers=None, params=None, json=None):
        """
        Make paginated search API calls until all results are retrieved.
        
        Args:
            url (str): API endpoint URL
            method (str): HTTP method (default: POST for search operations)
            retval (int): Expected successful status code (default: 200)
            headers (dict): HTTP headers
            params (dict): URL parameters
            json (dict): JSON payload containing search parameters
            
        Returns:
            Response: Mock response object with combined paginated results, or None if error
        """
        if headers is None:
            headers = self.headers

        self.__verbose_print__(f"Search Request: {json}")
            
        all_results = []
        combined_response = None
        # start_row = 0
        current_json = json.copy() if json else {}
        # current_json["search"]["numberOfResults"] = 2
        
        while True:
            try:
                self.__verbose_print__({
                    "json": current_json,
                    "url": url,
                    "method": method,
                    "headers": headers,
                    "params": params
                })
                response = requests.request(method, url, headers=headers, params=params, json=current_json)
                # print("-=" * 50)
                if response.status_code == retval:
                    response_data = response.json()
                    # print(response_data)
                    
                    # Initialize combined_response with first response
                    if combined_response is None:
                        combined_response = response_data.copy()
                    
                    # Determine the results key (could be 'users', 'entities', etc.)
                    results_key = None
                    for key in ['users', 'entities', 'applications', 'results']:
                        if key in response_data:
                            results_key = key
                            break
                    
                    if results_key:
                        # Add results from this page
                        page_results = response_data.get(results_key, [])
                        all_results.extend(page_results)
                    
                    # Check if there are more results
                    next_results = response_data.get("nextResults")
                    if not next_results:
                        break
                        
                    # Update the request for next page
                    # Remove queryString and other search params when using nextResults
                    if len(all_results) >= response_data["total"]:
                        break

                    current_json["search"] = {"nextResults": next_results}
                    # current_json["search"]["startRow"] = current_json["search"]["startRow"] + response_data["total"]
                else:
                    print(f"WARNING: {method} {url} - {response.status_code} - {response.text}")
                    return None
            except requests.RequestException as e:
                print(f"ERROR: {url} - {method} - {e}")
                return None
        
        # Update the combined response with all results
        if combined_response and results_key:
            combined_response[results_key] = all_results
            # Remove nextResults since we've fetched everything
            combined_response.pop("nextResults", None)
            
            # Create a mock response object with the combined data
            class MockResponse:
                def __init__(self, data):
                    self._data = data
                    self.status_code = retval
                
                def json(self):
                    return self._data
            
            return MockResponse(combined_response)
        
        return None

    def __verbose_print__(self, message):
        if self.verbose:
            print(f"DEBUG: {message}")

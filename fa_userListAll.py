#! /usr/bin/env python3

import json
import argparse
import os
import sys
from fusion_auth_client.fa_lib import fusion_auth_client

parser = argparse.ArgumentParser()
parser.add_argument("--api_key", type=str, default=os.getenv("FA_API_KEY"))
parser.add_argument("--api_host", type=str, default=os.getenv("FA_DOMAIN"))
parser.add_argument("--tenant_id", type=str, default=None)
parser.add_argument("--verbose", action="store_true", default=False)
args = parser.parse_args()

client = fusion_auth_client(args.api_host, args.api_key, args.tenant_id, args.verbose)
if not client:
    sys.exit("Failed to create FusionAuth client")

application = client.Applications.get("FusionAuth")
print(f"DEBUG - Application: {application['name']}")

application = client.Applications.get("3c219e58-ed0e-4b18-ad48-f4f92793ae32")
print(f"DEBUG - Application: {application['name']}")

# application = client.Applications.get("v1FrontEnd-app")
# print(f"DEBUG - Application: {application['name']}")

# application2 = client.Applications.get("e728c32c-bd27-4e04-b912-3df206bf5c80")
# print(f"DEBUG - Application2: {application2}")


# user = client.Users.get("mk@tenetic.com")
# print(f"DEBUG - User: {user}")

# users = client.Users.search()
# print(f"DEBUG - Users: {users}")



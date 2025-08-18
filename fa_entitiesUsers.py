#! /usr/bin/env python3

import json
import argparse
import os
import sys
from fusion_auth_client.fa_lib import fusion_auth_client

parser = argparse.ArgumentParser()
parser.add_argument("--api_key", type=str, default=os.getenv("FA_API_KEY"))
parser.add_argument("--api_host", type=str, default=os.getenv("FA_DOMAIN"))
parser.add_argument("--entity_name", type=str, required=True)
parser.add_argument("--tenant_id", type=str, default=None)
parser.add_argument("--verbose", action="store_true", default=False)
args = parser.parse_args()

client = fusion_auth_client(args.api_host, args.api_key, args.tenant_id, args.verbose)
if not client:
    sys.exit("Failed to create FusionAuth client")

entity_id = client.Entities.get_id(args.entity_name)
if not entity_id:
    sys.exit("Failed to get entity ID")
print(f"entity_id: {entity_id}")

users = client.Entities.get_user_grants_by_entity(entity_id, expand_user_email=True)
if not users:
    sys.exit("Failed to get users")
for user in users['grants']:
    print(f"{user['userEmail']}: {user['permissions']}")

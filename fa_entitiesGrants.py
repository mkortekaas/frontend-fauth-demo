#! /usr/bin/env python3

import json
import argparse
import os
import sys
from fusion_auth_client.fa_lib import fusion_auth_client

parser = argparse.ArgumentParser()
parser.add_argument("--api_key", type=str, default=os.getenv("FA_API_KEY"))
parser.add_argument("--api_host", type=str, default=os.getenv("FA_DOMAIN"))
parser.add_argument("--email", type=str, required=True)
parser.add_argument("--tenant_id", type=str, default=None)
parser.add_argument("--verbose", action="store_true", default=False)
args = parser.parse_args()

client = fusion_auth_client(args.api_host, args.api_key, args.tenant_id, args.verbose)
if not client:
    sys.exit("Failed to create FusionAuth client")

user_id = client.Users.get_id(args.email)
if not user_id:
    sys.exit("Failed to get user ID")
print(f"user_id: {user_id}")

grants = client.Entities.get_grants(user_id)
if not grants:
    sys.exit("Failed to get grants")
print(f"grants: {json.dumps(grants, indent=4)}")
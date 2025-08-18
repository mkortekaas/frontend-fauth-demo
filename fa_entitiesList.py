#! /usr/bin/env python3

import json
import argparse
import os
import sys
from fusion_auth_client.fa_lib import fusion_auth_client

parser = argparse.ArgumentParser()
parser.add_argument("--api_key", type=str, default=os.getenv("FA_API_KEY"))
parser.add_argument("--api_host", type=str, default=os.getenv("FA_DOMAIN"))
parser.add_argument("--app_name", type=str)
parser.add_argument("--tenant_id", type=str, default=None)
parser.add_argument("--verbose", action="store_true", default=False)
args = parser.parse_args()

client = fusion_auth_client(args.api_host, args.api_key, args.tenant_id, args.verbose)
if not client:
    sys.exit("Failed to create FusionAuth client")

entities = client.Entities.search("*")
if not entities:
    sys.exit("Failed to search for entities")

for entity in entities["entities"]:
    print(json.dumps(entity, indent=4))
    print("-" * 50)

print(f"Total entities found: {len(entities['entities'])}")

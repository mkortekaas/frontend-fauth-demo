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
parser.add_argument("--password", type=str, required=True)
parser.add_argument("--first_name", type=str, required=True)
parser.add_argument("--last_name", type=str, required=True)
parser.add_argument("--app_name", type=str, default=None)
parser.add_argument("--roles", type=str, default=None)
parser.add_argument("--tenant_id", type=str, default=None)
parser.add_argument("--entity_name", type=str, default=None)
parser.add_argument("--entity_permissions", type=str, default=None)
parser.add_argument("--verbose", action="store_true", default=False)
args = parser.parse_args()

client = fusion_auth_client(args.api_host, args.api_key, args.tenant_id, args.verbose)
if not client:
    sys.exit("Failed to create FusionAuth client")

print(f"Creating user {args.email} for {args.tenant_id} / {args.app_name}")

if args.app_name:
    application_id = client.Applications.get_id(args.app_name)
    if not application_id:
        sys.exit("Failed to get application ID")
    print(f"application_id: {application_id}")
else:
    application_id = None

if args.entity_name:
    entity_id = client.Entities.get_id(args.entity_name)
    if not entity_id:
        sys.exit("Failed to get entity ID")
    print(f"entity_id: {entity_id}")
else:
    entity_id = None

user = client.Users.create(args.email, args.password, args.first_name, args.last_name, application_id=application_id, entity_id=entity_id)
if not user:
    sys.exit("Failed to create user")

user_id = client.Users.get_id(args.email)
if not user_id:
    sys.exit("Failed to get user ID")
print(f"user_id: {user_id}")

# # get the application_id
# application_id = client.Applications.get_id(args.app_name)
# if not application_id:
#     sys.exit("Failed to get application ID")
# print(f"application_id: {application_id}")

# # Convert roles string to list if provided
# if args.app_name:
#     roles = [args.roles] if args.roles else None
#     status = client.Users.register_application(user_id, application_id, roles)
#     if not status:
#         sys.exit("Failed to register user")
#     print(f"status: {status}")

if args.entity_name:
    entity_id = client.Entities.get_id(args.entity_name)
    if not entity_id:
        sys.exit("Failed to get entity ID")
    print(f"entity_id: {entity_id}")
    status = client.Entities.grant(entity_id, user_id, args.entity_permissions)
    if not status:
        sys.exit("Failed to permission user")
    print(f"status: {status}")
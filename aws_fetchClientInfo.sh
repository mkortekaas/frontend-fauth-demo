#!/bin/bash

# this script is used to fetch the client info from the SSM parameter store and write it to a .env file
#   You will need to have already created the SSM parameters in the parameter store if you opt to do it this way
#   You can see the way I did this with the terraform code in the tofu directory in this repo
# one of your params you would then set the env variable FA_CLIENT_JSON to 

if [ -z "$AWS_PARAM_BASE" ]; then
    echo "AWS_PARAM_BASE is not set"
    exit 1
fi
if [ -z "$APP_NAME_LIST" ]; then
    echo "APP_NAME_LIST is not set"
    exit 1
fi

for app_name in $APP_NAME_LIST; do
    client_info=$(aws ssm get-parameter --name "${AWS_PARAM_BASE}/${app_name}" --with-decryption --query "Parameter.Value" --output text)
    echo "${app_name}=${client_info}" >> .env
done


#!/bin/bash

# this script is used to create the demo users in the FA environment

APP_PREFIX="v1FrontEnd-"

required_envs="FA_DOMAIN FA_API_KEY DEMO_USER_BASE DEMO_USER_DOMAIN"
for env in $required_envs; do
    if [ -z "${!env}" ]; then
        echo "Error: $env is not set"
        exit 1
    fi
done

user_create() {
    if [ "$1" == "default" ]; then
        ./fa_userCreate.py --app_name=${APP_PREFIX}${1} --roles=${2} --email=${3} --first_name=${2} --last_name=DemoDemo --password=password123 --entity_name=${4} --entity_permissions=${2}
    else
        # echo "${3}"
        ./fa_userCreate.py --tenant_id=${APP_PREFIX}${1} --app_name=${APP_PREFIX}${1} --roles=${2} --email=${3} --first_name=${2} --last_name=DemoDemo --password=password123
    fi
}

user_delete() {
    if [ "$1" == "default" ]; then
        ./fa_userDelete.py --email=${2}
    else
        ./fa_userDelete.py --tenant_id=${APP_PREFIX}${1} --email=${2}
    fi
}

## handle the default application
for entity_name in $APP_NAME_LIST; do
    if [ "$1" == "create" ]; then
    echo "Creating users for $entity_name"
        user_create default admin ${DEMO_USER_BASE}+${entity_name}-admin@${DEMO_USER_DOMAIN} entity-${entity_name}
        user_create default user ${DEMO_USER_BASE}+${entity_name}-user@${DEMO_USER_DOMAIN} entity-${entity_name}
        user_create default sales ${DEMO_USER_BASE}+${entity_name}-sales@${DEMO_USER_DOMAIN} entity-${entity_name}
    fi

    if [ "$1" == "delete" ]; then
        echo "Deleting users for $entity_name"
        user_delete default ${DEMO_USER_BASE}+${entity_name}-admin@${DEMO_USER_DOMAIN}
        user_delete default ${DEMO_USER_BASE}+${entity_name}-user@${DEMO_USER_DOMAIN}
        user_delete default ${DEMO_USER_BASE}+${entity_name}-sales@${DEMO_USER_DOMAIN}
    fi
done

# now the rest
for app_name in $APP_NAME_LIST; do
    # Skip default application
    if [ "$app_name" == "default" ]; then
        continue
    fi
    
    if [ "$1" == "create" ]; then
        echo "Creating users for $app_name"
        user_create $app_name admin ${DEMO_USER_BASE}+admin@${DEMO_USER_DOMAIN}
        user_create $app_name user ${DEMO_USER_BASE}+user@${DEMO_USER_DOMAIN}
        user_create $app_name sales ${DEMO_USER_BASE}+sales@${DEMO_USER_DOMAIN}
    fi

    if [ "$1" == "delete" ]; then
        echo "Deleting users for $app_name"
        user_delete $app_name ${DEMO_USER_BASE}+admin@${DEMO_USER_DOMAIN}
        user_delete $app_name ${DEMO_USER_BASE}+user@${DEMO_USER_DOMAIN}
        user_delete $app_name ${DEMO_USER_BASE}+sales@${DEMO_USER_DOMAIN}
    fi
done



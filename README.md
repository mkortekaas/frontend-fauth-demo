# frontend-fauth-demo
Python Flask app demonstrating FusionAuth login. 
- Configuration comes from a single environment variable `FA_CLIENT_JSON`.
- The navbar title and color are driven by `client_name` and `navbar_color`.
- This uses our own instance of `fusion_auth_client` instead of the standard fusion auth one
  - Partially because never sure which call to make and the [api documentation](https://fusionauth.io/docs/apis/) gets me the rest calls easily
  - Partially because we're mucking around with tenants and I can add the logic for that in with the init this way
  - Partially because I've added additional caching as well as other insert logic into the flow
  - Clearly decide for yourself if you want to self support or use the fusion auth supported one (you are likely best to use the supported one)
- There is a portion of the tofu scripts used to setup the FA in the [tofu](./tofu/) directory for illustration purposes

There are TWO separate ways that things are modeled out here:
- [Tenant Application](#tenant-example)
- [Entities Application](#entities-example)

## Local development
1. Create venv and install deps:
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r frontend-fauth-demo/requirements.txt
```
2. Create `.env` with `SECRET_KEY`, optional `PORT`, and `FA_CLIENT_JSON`:
```bash
# Optional envs that may be handy for other scripts in this directory
export FA_DOMAIN=https://XXXX.fusionauth.ios
export FA_API_KEY=XXXXX
export AWS_PARAM_BASE="/fa_client_info/dev"
export APP_NAME_LIST="app clienta clientb default"
export DEMO_USER_BASE=mark
export DEMO_USER_DOMAIN=daprimus.com

## Required for the python app to work
export SECRET_KEY=devsecret
export PORT=8080
export FA_CLIENT_JSON='{"issuer":"https://auth.example.com","client_id":"xxx","client_secret":"yyy","redirect_uri":"http://localhost:8080/auth/callback","api_key":"fsn_zzz","tenant_id":"default","client_name":"My Demo App","navbar_color":"#0d6efd"}'
```
3. Visit `http://localhost:8080` (after you have started up the correct example)

## Tenant Example
In the `tenant` directory you will find an example of using fusion auth tenants to manage your application
- Each application needs to reside in it's own tenant. For the sake of clarity have used the tenant and application name to match each other
- Users are bound to this tenant, such that user foo@bar.com 
  - would exist multiple times in your FA instance if they need to have access to multiple tenant/applications
  - and those instances would not have the same password unless they are either sourced from an identity-provider or you've set the user/password to be the same
- You will need to run separate applications for EACH variant you need of this which may/may not be what you are looking for
- The `TenantAdmin` link that appears for admins sends one to the [FAuth Tenant Manager Application](https://fusionauth.io/docs/lifecycle/manage-users/tenant-manager#:~:text=The%20Tenant%20Manager%20is%20an,gives%20access%20to%20all%20tenants.)
- Run the app:
```bash
export $(grep -v '^#' .env | xargs) || true
python -m tenant.main
```

## Entities Example
- In this model we have a single tenant
  - Probably simplist to use the 'Default' FA tenant
- There is a single application that all users would sign into
  - Regardless of what they have access to
- If a user has access to multiple entities you will need to model that out as part of your flow as have done here
- Run the app:
```bash
export $(grep -v '^#' .env | xargs) || true
python -m entities.main
```

## Docker
```bash
docker build -t fa-frontend-demo -f frontend-fauth-demo/Dockerfile .
docker run --rm -p 8080:8080 \
  -e SECRET_KEY=changeme \
  -e FA_CLIENT_JSON='{"issuer":"https://auth.example.com","client_id":"xxx","client_secret":"yyy","api_key":"fsn_zzz","tenant_id":"default","client_name":"My App","navbar_color":"#0d6efd"}' \
  fa-frontend-demo
```

## FusionAuth API client
The route `/fa/ping` demonstrates importing the client from `fusion_auth_client/fa_lib.py` and constructing it with `issuer` and `api_key` from `FA_CLIENT_JSON`.

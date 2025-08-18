resource "fusionauth_tenant" "frontend" {
  for_each = {
    for k, v in module.global-variables.fa_client_list_object : k => v
    if k != "default"
  }
  name                       = "v1FrontEnd-${each.key}"
}

resource "fusionauth_api_key" "frontend" {
  depends_on                 = [fusionauth_tenant.frontend]
  for_each                   = module.global-variables.fa_client_list_object
  name                       = "v1FrontEnd-${each.key}"
  tenant_id                  = each.key == "default" ? data.fusionauth_tenant.default.id : fusionauth_tenant.frontend[each.key].id
}

resource "fusionauth_application" "frontend" {
  depends_on                 = [fusionauth_tenant.frontend]
  for_each                   = module.global-variables.fa_client_list_object
  name                       = "v1FrontEnd-${each.key}"
  tenant_id                  = each.key == "default" ? data.fusionauth_tenant.default.id : fusionauth_tenant.frontend[each.key].id
  jwt_configuration {
    enabled                  = true
    refresh_token_ttl_minutes = 43200  # 30 days
    ttl_seconds     = 3600  # 1 hour for access tokens
  }
  lambda_configuration {
    access_token_populate_id = fusionauth_lambda.populate_jwt_with_scopes[each.key].id
    id_token_populate_id     = fusionauth_lambda.populate_jwt_with_scopes[each.key].id
  }
  oauth_configuration {
    generate_refresh_tokens  = true
    scope_handling_policy    = "Strict"
    unknown_scope_policy     = "Reject"
    # authorized_url_validation_policy = "AllowWildcards"  # vs ExactMatch
    authorized_url_validation_policy = "ExactMatch"
    authorized_redirect_urls = [
      "https://${each.key}.${var.hosting_domain}/api/auth/callback",
      "https://${each.key}.${var.hosting_domain}/auth/login",
      "http://localhost:8080/api/auth/callback",
      "http://localhost:8080/auth/login",
      "http://localhost:8080/auth/callback",
    ]
    enabled_grants           = ["authorization_code", "refresh_token"]
    
    provided_scope_policy {
      email {
        enabled  = true
        required = false
      }
      profile {
        enabled  = true
        required = false
      }
      address {
        enabled  = false
        required = false
      }
      phone {
        enabled  = false
        required = false
      }
    }
  }
}

resource "fusionauth_application_role" "app_admin" {
  depends_on                 = [fusionauth_application.frontend]
  for_each                   = module.global-variables.fa_client_list_object
  application_id             = fusionauth_application.frontend[each.key].id
  is_default                 = false
  is_super_role              = true
  name                       = "admin"
}
resource "fusionauth_application_role" "app_user" {
  depends_on                 = [fusionauth_application.frontend]
  for_each                   = module.global-variables.fa_client_list_object
  application_id             = fusionauth_application.frontend[each.key].id
  is_default                 = true
  is_super_role              = false
  name                       = "user"
}
resource "fusionauth_application_role" "app_sales" {
  depends_on                 = [fusionauth_application.frontend]
  for_each                   = module.global-variables.fa_client_list_object
  application_id             = fusionauth_application.frontend[each.key].id
  is_default                 = false
  is_super_role              = false
  name                       = "sales"
}

# Lambda function to populate JWT with standard OpenID Connect claims based on scopes
resource "fusionauth_lambda" "populate_jwt_with_scopes" {
  for_each = module.global-variables.fa_client_list_object
  name     = "Populate JWT with OpenID Connect claims - ${each.key}"
  type     = "JWTPopulate"
  debug    = false
  body     = <<-EOF
    // FusionAuth Lambda to populate JWT with OpenID Connect claims based on requested scopes
    function populate(jwt, user, registration, context) {

      // Get the API key from the environment variable
      var API_KEY = "${fusionauth_api_key.frontend[each.key].key}";

      // Helper to call FusionAuth locally (avoid 9011; use 9012 for local HTTP per docs)
      function getGrants(userId, tenantId) {
        var url = "http://localhost:9012/api/entity/grant/search?userId=" + userId;
        var headers = { "Authorization": API_KEY };
        // If you’re multi-tenant, pass the tenant header explicitly
        if (tenantId) { headers["X-FusionAuth-TenantId"] = tenantId; }
        var resp = fetch(url, { method: "GET", headers: headers });
        if (resp.status !== 200) { return null; }
        return JSON.parse(resp.body);
      }

      // Build a compact claim: [{entityId, permissions: ["read","write"]}, ...]
      var tenantId = (jwt.tid || user.tenantId); // tid is reserved but readable
      var grantsOut = [];
      var json = getGrants(user.id, tenantId);
      if (json && json.grants && json.grants.length) {
        for (var i = 0; i < json.grants.length; i++) {
          var g = json.grants[i];
          grantsOut.push({ entityId: g.entity.id, entityName: g.entity.name, permissions: g.permissions || [] });
        }
      }
      jwt.entity_grants = grantsOut;

      // Always include the basic claims
      jwt.sub = user.id;
      jwt.applicationId = registration?.applicationId;
      jwt.roles = registration?.roles || [];
      
      // Add email claims if 'email' scope was requested
      if (jwt.scope && jwt.scope.includes('email')) {
        jwt.email = user.email;
        jwt.email_verified = user.verified;
      }
      
      // Add profile claims if 'profile' scope was requested
      if (jwt.scope && jwt.scope.includes('profile')) {
        jwt.given_name = user.firstName;
        jwt.family_name = user.lastName;
        jwt.name = user.fullName || (user.firstName + ' ' + user.lastName);
        jwt.preferred_username = user.username;
        jwt.picture = user.imageUrl;
        jwt.updated_at = user.lastUpdateInstant;
      }
      
      // Add phone claims if 'phone' scope was requested
      if (jwt.scope && jwt.scope.includes('phone')) {
        jwt.phone_number = user.mobilePhone;
        jwt.phone_number_verified = false; // FusionAuth doesn't track phone verification by default
      }
      
      // Add address claims if 'address' scope was requested
      if (jwt.scope && jwt.scope.includes('address')) {
        // FusionAuth doesn't have built-in address fields, but you could add custom data here
        // jwt.address = user.data?.address;
      }
    }
  EOF
}

resource "aws_ssm_parameter" "fa_client_info" {
  for_each                   = module.global-variables.fa_client_list_object
  name                       = "/fa_client_info/${var.fa_environment}/${each.key}"
  type                       = "SecureString"
  value                      = jsonencode( {
    "app_name"               = fusionauth_application.frontend[each.key].name,
    "tenant_id"              = each.key == "default" ? data.fusionauth_tenant.default.id : fusionauth_tenant.frontend[each.key].id,
    "client_id"              = fusionauth_application.frontend[each.key].oauth_configuration[0].client_id,
    "client_secret"          = fusionauth_application.frontend[each.key].oauth_configuration[0].client_secret,
    "server_domain"          = var.fa_domain,
    "environment"            = var.fa_environment,
    "api_key"                = fusionauth_api_key.frontend[each.key].key,
    "navbar_color"           = each.value.navbar_color,
  })
}

resource "fusionauth_entity_type" "company" {
  name                       = "company"
}
resource "fusionauth_entity_type_permission" "user" {
  depends_on                 = [fusionauth_entity_type.company]
  entity_type_id             = fusionauth_entity_type.company.id
  name                       = "user"
  description                = "User permission"
  is_default                 = true
}
resource "fusionauth_entity_type_permission" "admin" {
  depends_on                 = [fusionauth_entity_type.company]
  entity_type_id             = fusionauth_entity_type.company.id
  name                       = "admin"
  description                = "Admin permission"
  is_default                 = false
}
resource "fusionauth_entity_type_permission" "sales" {
  depends_on                 = [fusionauth_entity_type.company]
  entity_type_id             = fusionauth_entity_type.company.id
  name                       = "sales"
  description                = "Sales permission"
  is_default                 = false
}

## each client gets an entity of type company
resource "fusionauth_entity" "entity" {
  depends_on                 = [fusionauth_entity_type.company]
  for_each                   = module.global-variables.fa_client_list_object
  name                       = "entity-${each.key}"
  tenant_id                  = data.fusionauth_tenant.default.id
  entity_type_id             = fusionauth_entity_type.company.id
}

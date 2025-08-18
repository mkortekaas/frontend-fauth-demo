import os
import json
import secrets
from urllib.parse import urljoin, urlencode

from flask import Flask, redirect, request, session, url_for, render_template, jsonify
from authlib.integrations.flask_client import OAuth
import requests
from dotenv import load_dotenv


load_dotenv()


def load_fa_config() -> dict:
    raw = (os.environ.get('FA_CLIENT_JSON')
           or os.environ.get('FA_CONFIG_JSON')
           or '').strip()
    if not raw:
        # Allow local development via .env if user uses python-dotenv
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {}
        return data
    except json.JSONDecodeError:
        return {}


def normalize_fa_cfg(cfg: dict) -> dict:
    """Normalize common key variants from FA client JSON."""
    if not cfg:
        return {}
    normalized = dict(cfg)
    # Server/issuer
    normalized['issuer'] = (
        cfg.get('issuer')
        or cfg.get('issuer_url')
        or cfg.get('server_domain')
        or cfg.get('server')
        or cfg.get('server_url')
        or cfg.get('fusionauth_base_url')
        or cfg.get('fusionauth_url')
    )
    # Client credentials
    normalized['client_id'] = cfg.get('client_id') or cfg.get('clientId')
    normalized['client_secret'] = cfg.get('client_secret') or cfg.get('clientSecret')
    # Redirect/callback
    normalized['redirect_uri'] = (
        cfg.get('redirect_uri')
        or cfg.get('redirect_url')
        or cfg.get('callback_url')
    )
    return normalized


def build_redirect_uri(app: Flask, configured_uri: str | None) -> str:
    if configured_uri:
        return configured_uri
    # Fallback: infer from current request or app config
    # Use request.url_root if in a request context; else default to localhost
    try:
        base_url = request.url_root  # only valid during a request
    except RuntimeError:
        base_url = f"http://localhost:{app.config.get('PORT', 8080)}/"
    return urljoin(base_url, 'auth/callback')


def _hex_to_rgb(value: str) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    # Normalize common formats: '#RRGGBB', 'RRGGBB', '0xRRGGBB'
    if s.startswith(('0x', '0X')) and len(s) == 8:
        s = '#' + s[2:]
    elif not s.startswith('#') and len(s) == 6:
        s = '#' + s
    if s.startswith('#') and len(s) == 7:
        try:
            r = int(s[1:3], 16)
            g = int(s[3:5], 16)
            b = int(s[5:7], 16)
            return (r, g, b)
        except ValueError:
            return None
    return None


def _is_light_color(hex_color: str) -> bool:
    rgb = _hex_to_rgb(hex_color)
    if not rgb:
        return False
    r, g, b = rgb
    # Perceived luminance
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return luminance > 186  # threshold; higher = light color


def _normalize_css_hex_color(value: str) -> str:
    """Return a CSS-safe hex color (e.g., '#RRGGBB') when possible.
    Accepts '#RRGGBB', 'RRGGBB', '0xRRGGBB'. Falls back to the original string if parsing fails.
    """
    rgb = _hex_to_rgb(value)
    if not rgb:
        return value
    r, g, b = rgb
    return f"#{r:02X}{g:02X}{b:02X}"


_NAV_COLOR_LOGGED = False


def create_app() -> Flask:
    app = Flask(__name__, template_folder='templates', static_folder='static')

    # Secrets & session
    app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = False  # set True when served over HTTPS
    app.config['PORT'] = int(os.environ.get('PORT', '8080'))

    # Load FusionAuth config
    fa_cfg = normalize_fa_cfg(load_fa_config())
    app.config['FA_CFG'] = fa_cfg

    # OIDC / OAuth client setup
    oauth = OAuth(app)
    issuer_base = fa_cfg.get('issuer')
    client_id = fa_cfg.get('client_id')
    client_secret = fa_cfg.get('client_secret')
    redirect_uri = build_redirect_uri(app, fa_cfg.get('redirect_uri'))
    authorize_url = None
    token_url = None
    jwks_uri = None
    discovery_url = None
    server_metadata = None

    if issuer_base:
        if not issuer_base.startswith(('http://', 'https://')):
            issuer_base = f"https://{issuer_base}"
        # Normalize issuer without trailing slash
        issuer_base = issuer_base.rstrip('/')
        # Try discovery first
        try:
            discovery_url = f"{issuer_base}/.well-known/openid-configuration"
            resp = requests.get(discovery_url, timeout=5)
            if resp.ok:
                disco = resp.json()
                server_metadata = disco
                authorize_url = disco.get('authorization_endpoint')
                token_url = disco.get('token_endpoint')
                jwks_uri = disco.get('jwks_uri')
        except requests.RequestException:
            pass
        # Fallback to conventional endpoints
        authorize_url = authorize_url or f"{issuer_base}/oauth2/authorize"
        token_url = token_url or f"{issuer_base}/oauth2/token"
        jwks_uri = jwks_uri or f"{issuer_base}/.well-known/jwks.json"
        if server_metadata is None:
            server_metadata = {
                'issuer': issuer_base,
                'authorization_endpoint': authorize_url,
                'token_endpoint': token_url,
                'jwks_uri': jwks_uri,
            }

    # Validate required configuration and register OAuth client
    if issuer_base and client_id and client_secret:
        register_kwargs = {
            'name': 'fusionauth',
            'client_id': client_id,
            'client_secret': client_secret,
            'client_kwargs': {'scope': 'openid profile email offline_access'},
        }
        if server_metadata and discovery_url:
            register_kwargs['server_metadata_url'] = discovery_url
        else:
            register_kwargs['server_metadata'] = server_metadata
        oauth.register(**register_kwargs)
    else:
        missing = []
        if not issuer_base:
            missing.append('server_domain/issuer')
        if not client_id:
            missing.append('client_id')
        if not client_secret:
            missing.append('client_secret')
        message = (
            'FusionAuth configuration missing required values: ' + ', '.join(missing) +
            '. Ensure FA_CLIENT_JSON (or FA_CONFIG_JSON) provides these.'
        )
        # Fail fast so misconfiguration is obvious at startup
        raise RuntimeError(message)

    @app.context_processor
    def inject_globals():
        cfg = app.config.get('FA_CFG', {})
        original_color = cfg.get('navbar_color', '#24292f')
        navbar_color_css = _normalize_css_hex_color(original_color)
        text_color = '#000000' if _is_light_color(navbar_color_css) else '#ffffff'
        global _NAV_COLOR_LOGGED
        if not _NAV_COLOR_LOGGED:
            app.logger.info(
                'Navbar color resolved: original=%s css=%s text=%s',
                original_color, navbar_color_css, text_color
            )
            _NAV_COLOR_LOGGED = True
        # Determine admin visibility from selected entity permissions
        id_claims = session.get('id_token_claims') or {}
        selected_entity = session.get('selected_entity')
        
        # Check for global admin role (fallback)
        roles = id_claims.get('roles') if isinstance(id_claims, dict) else None
        if not isinstance(roles, list):
            roles = []
        global_admin = 'admin' in roles
        
        # Check for entity-specific admin permissions
        entity_admin = False
        if selected_entity and isinstance(selected_entity, dict):
            entity_permissions = selected_entity.get('permissions', [])
            if isinstance(entity_permissions, list):
                entity_admin = 'admin' in entity_permissions
        
        # User is admin if they have either global or entity admin access
        is_admin = global_admin or entity_admin
        tenant_id_cfg = cfg.get('tenant_id')

        entity_grants = id_claims.get('entity_grants') if isinstance(id_claims, dict) else None
        if not isinstance(entity_grants, list):
            entity_grants = []

        # Entity grants handling
        selected_entity = session.get('selected_entity')
        entity_warning = False
        entity_selection_needed = False
        current_entity_name = None

        if len(entity_grants) == 0:
            entity_warning = True
        elif len(entity_grants) == 1:
            # Auto-select single entity if not already selected
            if not selected_entity:
                session['selected_entity'] = entity_grants[0]
                selected_entity = entity_grants[0]
            current_entity_name = selected_entity.get('entityName') if selected_entity else None
        elif len(entity_grants) > 1:
            if not selected_entity:
                entity_selection_needed = True
            else:
                current_entity_name = selected_entity.get('entityName')

        return {
            'app_name': cfg.get('client_name', 'My App'),
            'navbar_color': navbar_color_css,
            'navbar_text_color': text_color,
            'is_admin': is_admin,
            'entity_grants': entity_grants,
            'entity_warning': entity_warning,
            'entity_selection_needed': entity_selection_needed,
            'current_entity_name': current_entity_name,
            'selected_entity': selected_entity,
        }

    @app.route('/')
    def index():
        id_token_claims = session.get('id_token_claims')
        return render_template('index.html', id_token_claims=id_token_claims)

    @app.route('/signin')
    def signin():
        return render_template('signin.html')

    @app.route('/login')
    def login():
        client = getattr(oauth, 'fusionauth', None)
        if client is None:
            return render_template('error.html', message='FusionAuth OAuth client is not configured'), 500
        callback_url = build_redirect_uri(app, app.config['FA_CFG'].get('redirect_uri'))
        # Generate and store a nonce for OIDC ID token validation
        oidc_nonce = secrets.token_urlsafe(16)
        session['oidc_nonce'] = oidc_nonce
        return client.authorize_redirect(redirect_uri=callback_url, nonce=oidc_nonce)

    # Alias to satisfy post-logout redirect requirement: /auth/login
    @app.route('/auth/login')
    def auth_login_alias():
        return redirect(url_for('login'))

    @app.route('/auth/callback')
    def auth_callback():
        client = getattr(oauth, 'fusionauth', None)
        if client is None:
            return render_template('error.html', message='FusionAuth OAuth client is not configured'), 500

        token = client.authorize_access_token()
        id_claims = None
        try:
            oidc_nonce = session.pop('oidc_nonce', None)
            # Provide the nonce expected by OIDC validation
            id_claims = client.parse_id_token(token, nonce=oidc_nonce)
        except Exception as ex:
            app.logger.exception('ID token validation failed')
            return render_template('error.html', message=f'ID token validation failed: {ex}'), 400

        # Validate FusionAuth applicationId in claims matches configured client_id
        token_application_id = (id_claims or {}).get('applicationId')
        if not token_application_id or token_application_id != client_id:
            app.logger.error(
                'ApplicationId validation failed: token_application_id=%s expected_client_id=%s',
                token_application_id, client_id
            )
            # Clear any session data and provide clear error message
            session.clear()
            error_message = (
                'Authentication failed: You are not authorized to access this application. '
                'This may be because:\n\n'
                '• Your account is not registered for this specific application\n'
                '• Your account was registered for a different application\n'
                '• There is a configuration mismatch\n\n'
                'Please contact your administrator for assistance.'
            )
            return render_template('error.html', 
                                 message=error_message,
                                 show_retry=True,
                                 retry_url=url_for('login')), 403

        session['token'] = token
        session['id_token_claims'] = id_claims
        
        # Handle entity grants flow
        entity_grants = id_claims.get('entity_grants') if isinstance(id_claims, dict) else []
        if not isinstance(entity_grants, list):
            entity_grants = []
            
        if len(entity_grants) > 1:
            # Multiple entities - redirect to selection
            return redirect(url_for('select_entity'))
        elif len(entity_grants) == 1:
            # Single entity - auto-select
            session['selected_entity'] = entity_grants[0]
        # If no entities, the warning will be shown on the profile page
        
        return redirect(url_for('profile'))

    @app.route('/profile')
    def profile():
        id_token_claims = session.get('id_token_claims')
        token = session.get('token')
        if not id_token_claims:
            return redirect(url_for('index'))
        return render_template('profile.html', id_token_claims=id_token_claims, token=token)

    @app.route('/list_users')
    def list_users():
        # Entity admin-only view
        id_token_claims = session.get('id_token_claims') or {}
        selected_entity = session.get('selected_entity')
        
        # Check if user is authenticated and has a selected entity
        if not id_token_claims or not selected_entity:
            return redirect(url_for('index'))
        
        # Check if user has admin permissions for the selected entity
        entity_permissions = selected_entity.get('permissions', [])
        if not isinstance(entity_permissions, list) or 'admin' not in entity_permissions:
            return render_template('error.html', message='Admin access required for this entity'), 403

        # Build FusionAuth client
        try:
            base_dir = os.path.dirname(os.path.dirname(__file__))
            # Ensure the project root (containing the fusion_auth_client package) is on sys.path
            if base_dir not in os.sys.path:
                os.sys.path.append(base_dir)
            from fusion_auth_client.fa_lib import fusion_auth_client as FAClient  # type: ignore
        except Exception as ex:
            app.logger.exception('Unable to import FusionAuth client')
            return render_template('error.html', message=f'Unable to import FusionAuth client: {ex}')

        cfg = app.config.get('FA_CFG', {})
        issuer = cfg.get('issuer')
        api_key = cfg.get('api_key')
        tenant_id = cfg.get('tenant_id')

        if not (issuer and api_key):
            return render_template('error.html', message='Missing issuer or api_key in FA_CLIENT_JSON'), 500

        try:
            client = FAClient(server_url=issuer, api_key=api_key, tenant_id=tenant_id)
        except Exception as ex:
            app.logger.exception('Failed to create FusionAuth client')
            return render_template('error.html', message=f'Failed to create FusionAuth client: {ex}')

        # Get entity ID from selected entity
        entity_id = selected_entity.get('entityId')
        if not entity_id:
            return render_template('error.html', message='No entity ID found in selected entity'), 400

        users_result = None
        try:
            users_result = client.Entities.get_user_grants_by_entity(entity_id, expand_user_email=True)
        except Exception as ex:
            app.logger.exception('Entity user grants query failed')
            return render_template('error.html', message=f'Entity user grants query failed: {ex}')

        user_grants = []
        total = 0
        if isinstance(users_result, dict) and 'grants' in users_result:
            user_grants = users_result.get('grants', [])
            total = len(user_grants)

        return render_template('list_users.html', user_grants=user_grants, total=total, entity_name=selected_entity.get('entityName', 'Unknown Entity'))

    @app.route('/create_user')
    def create_user():
        """Show form to create a new user"""
        # Entity admin-only view
        id_token_claims = session.get('id_token_claims') or {}
        selected_entity = session.get('selected_entity')
        
        # Check if user is authenticated and has a selected entity
        if not id_token_claims or not selected_entity:
            return redirect(url_for('index'))
        
        # Check if user has admin permissions for the selected entity
        entity_permissions = selected_entity.get('permissions', [])
        if not isinstance(entity_permissions, list) or 'admin' not in entity_permissions:
            return render_template('error.html', message='Admin access required for this entity'), 403

        # Get available permissions for this entity
        entity_name = selected_entity.get('entityName', 'Unknown Entity')
        available_permissions = []
        
        try:
            # Build FusionAuth client to get entity permissions
            base_dir = os.path.dirname(os.path.dirname(__file__))
            if base_dir not in os.sys.path:
                os.sys.path.append(base_dir)
            from fusion_auth_client.fa_lib import fusion_auth_client as FAClient  # type: ignore
            
            cfg = app.config.get('FA_CFG', {})
            issuer = cfg.get('issuer')
            api_key = cfg.get('api_key')
            tenant_id = cfg.get('tenant_id')

            if issuer and api_key:
                client = FAClient(server_url=issuer, api_key=api_key, tenant_id=tenant_id)
                entity_search = client.Entities.get(entity_name)
                if entity_search and 'entities' in entity_search and len(entity_search['entities']) > 0:
                    entity_data = entity_search['entities'][0]
                    if 'type' in entity_data and 'permissions' in entity_data['type']:
                        available_permissions = [p['name'] for p in entity_data['type']['permissions']]
        except Exception as ex:
            app.logger.warning('Failed to load entity permissions for create form: %s', ex)
            # Fallback to common permissions if entity lookup fails
            available_permissions = ['admin', 'read', 'write', 'delete']

        return render_template('create_user.html', 
                             entity_name=entity_name, 
                             available_permissions=available_permissions)

    @app.route('/create_user', methods=['POST'])
    def create_user_post():
        """Process user creation"""
        # Entity admin-only view
        id_token_claims = session.get('id_token_claims') or {}
        selected_entity = session.get('selected_entity')
        
        # Check if user is authenticated and has a selected entity
        if not id_token_claims or not selected_entity:
            return redirect(url_for('index'))
        
        # Check if user has admin permissions for the selected entity
        entity_permissions = selected_entity.get('permissions', [])
        if not isinstance(entity_permissions, list) or 'admin' not in entity_permissions:
            return render_template('error.html', message='Admin access required for this entity'), 403

        # Get form data
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        permissions = request.form.getlist('permissions')

        # Validate form data
        if not all([email, password, first_name, last_name]):
            return render_template('create_user.html', 
                                 error='All fields are required',
                                 entity_name=selected_entity.get('entityName', 'Unknown Entity'))

        # Build FusionAuth client
        try:
            base_dir = os.path.dirname(os.path.dirname(__file__))
            if base_dir not in os.sys.path:
                os.sys.path.append(base_dir)
            from fusion_auth_client.fa_lib import fusion_auth_client as FAClient  # type: ignore
        except Exception as ex:
            app.logger.exception('Unable to import FusionAuth client')
            return render_template('error.html', message=f'Unable to import FusionAuth client: {ex}')

        cfg = app.config.get('FA_CFG', {})
        issuer = cfg.get('issuer')
        api_key = cfg.get('api_key')
        tenant_id = cfg.get('tenant_id')
        application_id = cfg.get('client_id')

        if not (issuer and api_key):
            return render_template('error.html', message='Missing issuer or api_key in FA_CLIENT_JSON'), 500

        try:
            client = FAClient(server_url=issuer, api_key=api_key, tenant_id=tenant_id)
        except Exception as ex:
            app.logger.exception('Failed to create FusionAuth client')
            return render_template('error.html', message=f'Failed to create FusionAuth client: {ex}')

        # Get entity ID from selected entity
        entity_id = selected_entity.get('entityId')
        if not entity_id:
            return render_template('error.html', message='No entity ID found in selected entity'), 400

        try:
            # Create the user with application and entity registration
            user_result = client.Users.create(
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                application_id=application_id,
                entity_id=entity_id
            )
            
            if not user_result:
                return render_template('create_user.html', 
                                     error='Failed to create user. User may already exist.',
                                     entity_name=selected_entity.get('entityName', 'Unknown Entity'))

            user_id = user_result['user']['id']

            # Set entity permissions if specified
            if permissions:
                grant_result = client.Entities.grant(entity_id, user_id, permissions)
                if not grant_result:
                    app.logger.warning('User created but failed to set entity permissions')

            app.logger.info('Successfully created user: %s for entity: %s', email, selected_entity.get('entityName'))
            return redirect(url_for('list_users'))

        except Exception as ex:
            app.logger.exception('User creation failed')
            return render_template('create_user.html', 
                                 error=f'User creation failed: {ex}',
                                 entity_name=selected_entity.get('entityName', 'Unknown Entity'))

    @app.route('/delete_user/<user_id>', methods=['POST'])
    def delete_user(user_id):
        """Delete a user"""
        # Entity admin-only view
        id_token_claims = session.get('id_token_claims') or {}
        selected_entity = session.get('selected_entity')
        
        # Check if user is authenticated and has a selected entity
        if not id_token_claims or not selected_entity:
            return redirect(url_for('index'))
        
        # Check if user has admin permissions for the selected entity
        entity_permissions = selected_entity.get('permissions', [])
        if not isinstance(entity_permissions, list) or 'admin' not in entity_permissions:
            return render_template('error.html', message='Admin access required for this entity'), 403

        # Build FusionAuth client
        try:
            base_dir = os.path.dirname(os.path.dirname(__file__))
            if base_dir not in os.sys.path:
                os.sys.path.append(base_dir)
            from fusion_auth_client.fa_lib import fusion_auth_client as FAClient  # type: ignore
        except Exception as ex:
            app.logger.exception('Unable to import FusionAuth client')
            return render_template('error.html', message=f'Unable to import FusionAuth client: {ex}')

        cfg = app.config.get('FA_CFG', {})
        issuer = cfg.get('issuer')
        api_key = cfg.get('api_key')
        tenant_id = cfg.get('tenant_id')

        if not (issuer and api_key):
            return render_template('error.html', message='Missing issuer or api_key in FA_CLIENT_JSON'), 500

        try:
            client = FAClient(server_url=issuer, api_key=api_key, tenant_id=tenant_id)
        except Exception as ex:
            app.logger.exception('Failed to create FusionAuth client')
            return render_template('error.html', message=f'Failed to create FusionAuth client: {ex}')

        try:
            result = client.Users.delete(user_id)
            if result:
                app.logger.info('Successfully deleted user: %s', user_id)
            else:
                app.logger.warning('Failed to delete user: %s', user_id)
            
            return redirect(url_for('list_users'))

        except Exception as ex:
            app.logger.exception('User deletion failed')
            return render_template('error.html', message=f'User deletion failed: {ex}')

    @app.route('/edit_user_permissions/<user_id>')
    def edit_user_permissions(user_id):
        """Show form to edit user permissions for the current entity"""
        # Entity admin-only view
        id_token_claims = session.get('id_token_claims') or {}
        selected_entity = session.get('selected_entity')
        
        # Check if user is authenticated and has a selected entity
        if not id_token_claims or not selected_entity:
            return redirect(url_for('index'))
        
        # Check if user has admin permissions for the selected entity
        entity_permissions = selected_entity.get('permissions', [])
        if not isinstance(entity_permissions, list) or 'admin' not in entity_permissions:
            return render_template('error.html', message='Admin access required for this entity'), 403

        # Build FusionAuth client
        try:
            base_dir = os.path.dirname(os.path.dirname(__file__))
            if base_dir not in os.sys.path:
                os.sys.path.append(base_dir)
            from fusion_auth_client.fa_lib import fusion_auth_client as FAClient  # type: ignore
        except Exception as ex:
            app.logger.exception('Unable to import FusionAuth client')
            return render_template('error.html', message=f'Unable to import FusionAuth client: {ex}')

        cfg = app.config.get('FA_CFG', {})
        issuer = cfg.get('issuer')
        api_key = cfg.get('api_key')
        tenant_id = cfg.get('tenant_id')

        if not (issuer and api_key):
            return render_template('error.html', message='Missing issuer or api_key in FA_CLIENT_JSON'), 500

        try:
            client = FAClient(server_url=issuer, api_key=api_key, tenant_id=tenant_id)
        except Exception as ex:
            app.logger.exception('Failed to create FusionAuth client')
            return render_template('error.html', message=f'Failed to create FusionAuth client: {ex}')

        # Get entity ID from selected entity
        entity_id = selected_entity.get('entityId')
        entity_name = selected_entity.get('entityName', 'Unknown Entity')
        
        try:
            # Get user details
            user_details = client.Users.get(user_id)
            if not user_details:
                return render_template('error.html', message='User not found'), 404
                
            user_email = user_details['user']['email']
            user_name = f"{user_details['user'].get('firstName', '')} {user_details['user'].get('lastName', '')}".strip()

            # Get current user grants for this entity (using same method as list_users)
            entity_grants_result = client.Entities.get_user_grants_by_entity(entity_id, expand_user_email=True)
            current_permissions = []
            if entity_grants_result and 'grants' in entity_grants_result:
                for grant in entity_grants_result['grants']:
                    if grant.get('userId') == user_id:
                        current_permissions.extend(grant.get('permissions', []))

            # Get entity details to find available permissions
            entity_search = client.Entities.get(entity_name)
            available_permissions = []
            if entity_search and 'entities' in entity_search and len(entity_search['entities']) > 0:
                entity_data = entity_search['entities'][0]
                if 'type' in entity_data and 'permissions' in entity_data['type']:
                    available_permissions = [p['name'] for p in entity_data['type']['permissions']]

            return render_template('edit_user_permissions.html', 
                                 user_id=user_id,
                                 user_email=user_email,
                                 user_name=user_name,
                                 entity_name=entity_name,
                                 available_permissions=available_permissions,
                                 current_permissions=current_permissions)

        except Exception as ex:
            app.logger.exception('Failed to load user permissions')
            return render_template('error.html', message=f'Failed to load user permissions: {ex}')

    @app.route('/edit_user_permissions/<user_id>', methods=['POST'])
    def edit_user_permissions_post(user_id):
        """Process user permission updates"""
        # Entity admin-only view
        id_token_claims = session.get('id_token_claims') or {}
        selected_entity = session.get('selected_entity')
        
        # Check if user is authenticated and has a selected entity
        if not id_token_claims or not selected_entity:
            return redirect(url_for('index'))
        
        # Check if user has admin permissions for the selected entity
        entity_permissions = selected_entity.get('permissions', [])
        if not isinstance(entity_permissions, list) or 'admin' not in entity_permissions:
            return render_template('error.html', message='Admin access required for this entity'), 403

        # Get form data
        permissions = request.form.getlist('permissions')

        # Build FusionAuth client
        try:
            base_dir = os.path.dirname(os.path.dirname(__file__))
            if base_dir not in os.sys.path:
                os.sys.path.append(base_dir)
            from fusion_auth_client.fa_lib import fusion_auth_client as FAClient  # type: ignore
        except Exception as ex:
            app.logger.exception('Unable to import FusionAuth client')
            return render_template('error.html', message=f'Unable to import FusionAuth client: {ex}')

        cfg = app.config.get('FA_CFG', {})
        issuer = cfg.get('issuer')
        api_key = cfg.get('api_key')
        tenant_id = cfg.get('tenant_id')

        if not (issuer and api_key):
            return render_template('error.html', message='Missing issuer or api_key in FA_CLIENT_JSON'), 500

        try:
            client = FAClient(server_url=issuer, api_key=api_key, tenant_id=tenant_id)
        except Exception as ex:
            app.logger.exception('Failed to create FusionAuth client')
            return render_template('error.html', message=f'Failed to create FusionAuth client: {ex}')

        # Get entity ID from selected entity
        entity_id = selected_entity.get('entityId')
        
        try:
            # Update entity permissions (this replaces the current permission set)
            result = client.Entities.grant(entity_id, user_id, permissions)
            
            if result:
                app.logger.info('Successfully updated permissions for user: %s', user_id)
            else:
                app.logger.warning('Failed to update permissions for user: %s', user_id)
            
            return redirect(url_for('list_users'))

        except Exception as ex:
            app.logger.exception('Permission update failed')
            return render_template('error.html', message=f'Permission update failed: {ex}')

    @app.route('/select_entity')
    def select_entity():
        id_token_claims = session.get('id_token_claims')
        if not id_token_claims:
            return redirect(url_for('index'))
        
        entity_grants = id_token_claims.get('entity_grants', [])
        if not isinstance(entity_grants, list):
            entity_grants = []
            
        if len(entity_grants) <= 1:
            # No selection needed
            return redirect(url_for('profile'))
            
        return render_template('select_entity.html', entity_grants=entity_grants)

    @app.route('/select_entity', methods=['POST'])
    def select_entity_post():
        id_token_claims = session.get('id_token_claims')
        if not id_token_claims:
            return redirect(url_for('index'))
        
        entity_grants = id_token_claims.get('entity_grants', [])
        if not isinstance(entity_grants, list):
            entity_grants = []
            
        selected_entity_id = request.form.get('entity_id')
        if not selected_entity_id:
            return redirect(url_for('select_entity'))
            
        # Find the selected entity
        selected_entity = None
        for entity in entity_grants:
            if entity.get('entityId') == selected_entity_id:
                selected_entity = entity
                break
                
        if selected_entity:
            session['selected_entity'] = selected_entity
            
        return redirect(url_for('profile'))

    @app.route('/reset_entity')
    def reset_entity():
        """Reset entity selection - useful for testing or changing entities"""
        id_token_claims = session.get('id_token_claims')
        if not id_token_claims:
            return redirect(url_for('index'))
        
        # Clear selected entity from session
        session.pop('selected_entity', None)
        
        # Redirect based on available entities
        entity_grants = id_token_claims.get('entity_grants', [])
        if not isinstance(entity_grants, list):
            entity_grants = []
            
        if len(entity_grants) > 1:
            return redirect(url_for('select_entity'))
        else:
            return redirect(url_for('profile'))

    @app.route('/logout')
    def logout():
        # Build provider logout URL if possible
        id_token = None
        token = session.get('token')
        if isinstance(token, dict):
            id_token = token.get('id_token')

        if issuer_base:
            # Post-logout must return to our hostname /auth/login
            logout_redirect = url_for('auth_login_alias', _external=True)

            # Prefer OIDC end_session_endpoint when available; fallback to FusionAuth's /oauth2/logout
            end_session_endpoint = None
            try:
                nonlocal server_metadata
            except Exception:
                server_metadata_local = None
            else:
                server_metadata_local = server_metadata

            if server_metadata_local and server_metadata_local.get('end_session_endpoint'):
                end_session_endpoint = server_metadata_local.get('end_session_endpoint')
            else:
                end_session_endpoint = f"{issuer_base}/oauth2/logout"

            params = {
                'client_id': client_id,
                'post_logout_redirect_uri': logout_redirect,
            }
            if id_token:
                params['id_token_hint'] = id_token

            query = urlencode(params, safe=':/')
            logout_url = f"{end_session_endpoint}?{query}"

            app.logger.info('Logout: endpoint=%s params=%s', end_session_endpoint, {k: ('<redacted>' if k == 'id_token_hint' else v) for k, v in params.items()})

            session.clear()
            return redirect(logout_url)

        # Default local logout
        session.clear()
        return redirect(url_for('index'))

    @app.route('/health')
    def health():
        return jsonify({"status": "ok"})

    # Example endpoint showing how to initialize the provided FusionAuth API client
    @app.route('/fa/ping')
    def fa_ping():
        # We won't make a real API call here, just validate we can construct the client
        try:
            base_dir = os.path.dirname(os.path.dirname(__file__))
            if base_dir not in os.sys.path:
                os.sys.path.append(base_dir)
            from fusion_auth_client.fa_lib import fusion_auth_client as FAClient  # type: ignore
        except Exception as ex:
            app.logger.exception('Unable to import FusionAuth client')
            return jsonify({"ok": False, "error": f"Unable to import FusionAuth client: {ex}"}), 500

        cfg = app.config.get('FA_CFG', {})
        api_key = cfg.get('api_key')
        if not (issuer_base and api_key):
            return jsonify({"ok": False, "error": "Missing issuer or api_key in FA_CLIENT_JSON"}), 400
        try:
            _client = FAClient(server_url=issuer_base, api_key=api_key, tenant_id=cfg.get('tenant_id'))
            return jsonify({"ok": True})
        except Exception as ex:
            return jsonify({"ok": False, "error": str(ex)}), 500

    @app.route('/api/current_entity')
    def current_entity_api():
        """API endpoint to get current entity information"""
        id_token_claims = session.get('id_token_claims')
        selected_entity = session.get('selected_entity')
        
        if not id_token_claims:
            return jsonify({"error": "Not authenticated"}), 401
            
        entity_grants = id_token_claims.get('entity_grants', [])
        if not isinstance(entity_grants, list):
            entity_grants = []
            
        return jsonify({
            "selected_entity": selected_entity,
            "entity_grants": entity_grants,
            "has_entities": len(entity_grants) > 0,
            "needs_selection": len(entity_grants) > 1 and not selected_entity
        })

    return app


def get_current_entity():
    """Utility function to get the current selected entity"""
    return session.get('selected_entity')


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app.config.get('PORT', 8080), debug=True)



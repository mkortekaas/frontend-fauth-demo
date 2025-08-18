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
        # Determine admin visibility from ID token claims
        id_claims = session.get('id_token_claims') or {}
        roles = id_claims.get('roles') if isinstance(id_claims, dict) else None
        if not isinstance(roles, list):
            roles = []
        is_admin = 'admin' in roles
        tenant_admin_url = None
        tenant_id_cfg = cfg.get('tenant_id')
        if is_admin and issuer_base and tenant_id_cfg:
            tenant_admin_url = f"{issuer_base}/tenant-manager/{tenant_id_cfg}"
        return {
            'app_name': cfg.get('client_name', 'My App'),
            'navbar_color': navbar_color_css,
            'navbar_text_color': text_color,
            'is_admin': is_admin,
            'tenant_admin_url': tenant_admin_url,
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
            # Clear any session data and force logout to allow a clean retry
            session.clear()
            return redirect(url_for('logout'))

        session['token'] = token
        session['id_token_claims'] = id_claims
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
        # Admin-only view
        id_token_claims = session.get('id_token_claims') or {}
        roles = id_token_claims.get('roles') if isinstance(id_token_claims, dict) else []
        if not isinstance(roles, list) or 'admin' not in roles:
            return redirect(url_for('index'))

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
        application_id = cfg.get('client_id')

        if not (issuer and api_key):
            return render_template('error.html', message='Missing issuer or api_key in FA_CLIENT_JSON'), 500

        try:
            client = FAClient(server_url=issuer, api_key=api_key, tenant_id=tenant_id)
        except Exception as ex:
            app.logger.exception('Failed to create FusionAuth client')
            return render_template('error.html', message=f'Failed to create FusionAuth client: {ex}')

        users_result = None
        try:
            users_result = client.Users.search(application_id=application_id, number_of_results=100, expand_registrations=True)
        except Exception as ex:
            app.logger.exception('User search failed')
            return render_template('error.html', message=f'User search failed: {ex}')

        users = []
        total = 0
        if isinstance(users_result, dict):
            users = users_result.get('users') or []
            total = users_result.get('total') or len(users)

        return render_template('list_users.html', users=users, total=total)

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

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app.config.get('PORT', 8080), debug=True)



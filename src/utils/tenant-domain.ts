// Accepted Auth0 tenant management-domain suffixes.
//
// The tool builds Auth0 Management API URLs (https://<domain>/api/v2/..., and
// the token endpoint https://<domain>/oauth/token) directly from this domain,
// so it must be a host that actually serves the Management API:
//   - `*.auth0.com`    — canonical tenant domains (e.g. tenant.us.auth0.com)
//   - `*.auth0app.com` — demo/sandbox platform tenants (e.g. the CIC demo
//                        platform: <tenant>.cic-demo-platform.auth0app.com)
//
// Any other hostname (arbitrary custom/vanity domains) is rejected.
export const TENANT_DOMAIN_PATTERN = /^[a-zA-Z0-9.-]+\.auth0(?:app)?\.com$/;

export function isValidTenantDomain(domain: string): boolean {
  return TENANT_DOMAIN_PATTERN.test(domain);
}

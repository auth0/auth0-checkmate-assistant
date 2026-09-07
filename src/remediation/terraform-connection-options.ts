interface AttributeSchema {
  terraformName?: string;
  sensitive?: boolean;
}

interface BlockSchema {
  attributes?: Readonly<Record<string, AttributeSchema>>;
  blocks?: Readonly<Record<string, BlockSchema>>;
}

const attribute = (
  terraformName?: string,
  sensitive = false,
): AttributeSchema => ({
  ...(terraformName ? { terraformName } : {}),
  ...(sensitive ? { sensitive } : {}),
});

const attributes = (
  names: readonly string[],
): Readonly<Record<string, AttributeSchema>> =>
  Object.fromEntries(names.map((name) => [name, attribute()]));

const flatBlock = (
  names: readonly string[],
  sensitiveNames: readonly string[] = [],
): BlockSchema => ({
  attributes: Object.fromEntries(
    names.map((name) => [
      name,
      attribute(undefined, sensitiveNames.includes(name)),
    ]),
  ),
});

const ROOT_BLOCKS: Readonly<Record<string, BlockSchema>> = {
  attribute_map: flatBlock(["attributes", "mapping_mode", "userinfo_scope"]),
  attributes: {
    blocks: {
      email: {
        attributes: attributes([
          "profile_required",
          "unique",
          "verification_method",
        ]),
        blocks: {
          identifier: flatBlock(["active", "default_method"]),
          signup: {
            attributes: attributes(["status"]),
            blocks: {
              verification: flatBlock(["active"]),
            },
          },
        },
      },
      phone_number: {
        attributes: attributes(["profile_required"]),
        blocks: {
          identifier: flatBlock(["active", "default_method"]),
          signup: {
            attributes: attributes(["status"]),
            blocks: {
              verification: flatBlock(["active"]),
            },
          },
        },
      },
      username: {
        attributes: attributes(["profile_required"]),
        blocks: {
          identifier: flatBlock(["active", "default_method"]),
          signup: flatBlock(["status"]),
          validation: {
            attributes: attributes(["max_length", "min_length"]),
            blocks: {
              allowed_types: flatBlock(["email", "phone_number"]),
            },
          },
        },
      },
    },
  },
  authentication_methods: {
    blocks: {
      email_otp: flatBlock(["enabled"]),
      passkey: flatBlock(["enabled"]),
      password: flatBlock(["api_behavior", "enabled", "signup_behavior"]),
      phone_otp: flatBlock(["enabled"]),
    },
  },
  connection_settings: flatBlock(["pkce"]),
  custom_headers: flatBlock(["header", "value"]),
  custom_password_hash: flatBlock(["action_id"]),
  decryption_key: flatBlock(["cert", "key"], ["key"]),
  federated_connections_access_tokens: flatBlock(["active"]),
  gateway_authentication: flatBlock(
    ["audience", "method", "secret", "secret_base64_encoded", "subject"],
    ["secret"],
  ),
  idp_initiated: flatBlock([
    "client_authorize_query",
    "client_id",
    "client_protocol",
    "enabled",
  ]),
  mfa: flatBlock(["active", "return_enroll_settings"]),
  passkey_options: flatBlock([
    "challenge_ui",
    "local_enrollment_enabled",
    "progressive_enrollment_enabled",
  ]),
  password_complexity_options: flatBlock(["min_length"]),
  password_dictionary: flatBlock(["dictionary", "enable"]),
  password_history: flatBlock(["enable", "size"]),
  password_no_personal_info: flatBlock(["enable"]),
  password_options: {
    blocks: {
      complexity: flatBlock([
        "character_type_rule",
        "character_types",
        "identical_characters",
        "max_length_exceeded",
        "min_length",
        "sequential_characters",
      ]),
      dictionary: flatBlock(["active", "custom", "default"]),
      history: flatBlock(["active", "size"]),
      profile_data: flatBlock(["active", "blocked_fields"]),
    },
  },
  signing_key: flatBlock(["cert", "key"], ["key"]),
  totp: flatBlock(["length", "time_step"]),
  validation: {
    blocks: {
      username: flatBlock(["max", "min"]),
    },
  },
};

const ROOT_ATTRIBUTE_NAMES = [
  "access_token_url",
  "adfs_server",
  "allowed_audiences",
  "api_enable_groups",
  "api_enable_users",
  "app_id",
  "auth_params",
  "authorization_endpoint",
  "brute_force_protection",
  "client_id",
  "client_secret",
  "community_base_url",
  "configuration",
  "consumer_key",
  "consumer_secret",
  "custom_scripts",
  "debug",
  "destination_url",
  "digest_algorithm",
  "disable_cache",
  "disable_self_service_change_password",
  "disable_sign_out",
  "disable_signup",
  "discovery_url",
  "domain",
  "domain_aliases",
  "dpop_signing_alg",
  "email",
  "enable_script_context",
  "enabled_database_customization",
  "entity_id",
  "fed_metadata_xml",
  "fields_map",
  "forward_request_info",
  "from",
  "gateway_url",
  "global_token_revocation_jwt_iss",
  "global_token_revocation_jwt_sub",
  "icon_url",
  "id_token_session_expiry_supported",
  "id_token_signed_response_algs",
  "identity_api",
  "import_mode",
  "ips",
  "issuer",
  "jwks_uri",
  "key_id",
  "map_user_id_to_id",
  "max_groups_to_retrieve",
  "messaging_service_sid",
  "metadata_url",
  "metadata_xml",
  "name",
  "non_persistent_attrs",
  "password_policy",
  "ping_federate_base_url",
  "pkce_enabled",
  "precedence",
  "protocol_binding",
  "provider",
  "realm_fallback",
  "recipient_url",
  "request_template",
  "request_token_url",
  "requires_username",
  "scopes",
  "scripts",
  "send_back_channel_nonce",
  "session_key",
  "set_user_root_attributes",
  "should_trust_email_verified_connection",
  "sign_in_endpoint",
  "sign_out_endpoint",
  "sign_saml_request",
  "signature_algorithm",
  "signature_method",
  "signing_cert",
  "strategy_version",
  "subject",
  "syntax",
  "team_id",
  "template",
  "tenant_domain",
  "token_endpoint",
  "token_endpoint_auth_method",
  "token_endpoint_auth_signing_alg",
  "token_endpoint_jwtca_aud_format",
  "twilio_sid",
  "twilio_token",
  "type",
  "upstream_params",
  "use_cert_auth",
  "use_kerberos",
  "use_oauth_spec_scope",
  "use_wsfed",
  "user_authorization_url",
  "user_id_attribute",
  "userinfo_endpoint",
  "waad_common_endpoint",
  "waad_protocol",
] as const;

const ROOT_ATTRIBUTES: Readonly<Record<string, AttributeSchema>> = {
  ...attributes(ROOT_ATTRIBUTE_NAMES),
  client_secret: attribute(undefined, true),
  configuration: attribute(undefined, true),
  consumer_secret: attribute(undefined, true),
  twilio_token: attribute(undefined, true),
  enabledDatabaseCustomization: attribute("enabled_database_customization"),
  customScripts: attribute("custom_scripts"),
  passwordPolicy: attribute("password_policy"),
};

const ROOT_SCHEMA: BlockSchema = {
  attributes: ROOT_ATTRIBUTES,
  blocks: ROOT_BLOCKS,
};

function record(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(
      `Terraform cannot represent the Auth0 connection option at ${path}.`,
    );
  }
  return value as Record<string, unknown>;
}

function hclString(value: string): string {
  return JSON.stringify(value);
}

function hclLiteral(value: unknown, path: string): string {
  if (value === null || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`Terraform received a non-finite number at ${path}.`);
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return hclString(value);
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => hclLiteral(item, `${path}[${index}]`)).join(", ")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(
      ([left], [right]) => left.localeCompare(right),
    );
    return `{ ${entries
      .map(
        ([key, nested]) =>
          `${hclString(key)} = ${hclLiteral(nested, `${path}.${key}`)}`,
      )
      .join(", ")} }`;
  }
  throw new Error(`Terraform cannot represent the value at ${path}.`);
}

function dataExpression(
  label: string,
  terraformPath: readonly string[],
): string {
  return `data.auth0_connection.${label}.options[0].${terraformPath.join("[0].")}`;
}

function renderBlock(
  value: unknown,
  schema: BlockSchema,
  label: string,
  apiPath: readonly string[],
  terraformPath: readonly string[],
  indent: number,
): string[] {
  const values = Array.isArray(value) ? value : [value];
  return values.flatMap((item, index) => {
    const source = record(item, [...apiPath, String(index)].join("."));
    const lines: string[] = [];
    for (const [apiName, nested] of Object.entries(source).sort(
      ([left], [right]) => left.localeCompare(right),
    )) {
      const attributeSchema = schema.attributes?.[apiName];
      const blockSchema = schema.blocks?.[apiName];
      if (!attributeSchema && !blockSchema) {
        throw new Error(
          `Terraform provider ${AUTH0_PROVIDER_SCHEMA_VERSION} has no schema for connection option "${[...apiPath, apiName].join(".")}". The Auth0 API returned this field but the Terraform provider does not model it, so it cannot be safely represented in Terraform (typically a connection feature newer than the pinned provider).`,
        );
      }
      const padding = " ".repeat(indent);
      if (attributeSchema) {
        const terraformName = attributeSchema.terraformName ?? apiName;
        const rendered = attributeSchema.sensitive
          ? dataExpression(label, [...terraformPath, terraformName])
          : hclLiteral(nested, [...apiPath, apiName].join("."));
        lines.push(`${padding}${terraformName} = ${rendered}`);
      } else if (blockSchema) {
        const instances = Array.isArray(nested) ? nested : [nested];
        for (
          let nestedIndex = 0;
          nestedIndex < instances.length;
          nestedIndex += 1
        ) {
          lines.push(`${padding}${apiName} {`);
          lines.push(
            ...renderBlock(
              instances[nestedIndex],
              blockSchema,
              label,
              [...apiPath, apiName],
              [...terraformPath, apiName],
              indent + 2,
            ),
          );
          lines.push(`${padding}}`);
        }
      }
    }
    return lines;
  });
}

export const AUTH0_PROVIDER_SCHEMA_VERSION = "1.52.0";

export function renderCompleteConnectionOptions(
  options: unknown,
  terraformLabel: string,
): string {
  const source = record(options, "options");
  const lines = renderBlock(
    source,
    ROOT_SCHEMA,
    terraformLabel,
    ["options"],
    [],
    4,
  );
  if (lines.length === 0) {
    throw new Error(
      "Terraform cannot safely manage a connection with an empty options snapshot.",
    );
  }
  return lines.join("\n");
}

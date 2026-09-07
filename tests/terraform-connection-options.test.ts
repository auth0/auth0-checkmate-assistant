import { describe, expect, it } from "vitest";
import { renderCompleteConnectionOptions } from "../src/remediation/terraform-connection-options.js";

describe("complete Terraform connection options", () => {
  it("renders complete native-database options with nested siblings", () => {
    const terraform = renderCompleteConnectionOptions(
      {
        mfa: { active: true, return_enroll_settings: true },
        import_mode: false,
        configuration: { private_key: "do-not-embed" },
        enabledDatabaseCustomization: false,
        customScripts: { login: "function login() {}" },
        passwordPolicy: "good",
        passkey_options: {
          challenge_ui: "both",
          local_enrollment_enabled: true,
          progressive_enrollment_enabled: true,
        },
        authentication_methods: {
          email_otp: { enabled: false },
          passkey: { enabled: true },
          password: {
            api_behavior: "allow",
            enabled: true,
            signup_behavior: "allow",
          },
          phone_otp: { enabled: false },
        },
        attributes: {
          email: {
            identifier: { active: true, default_method: "password" },
            profile_required: true,
            signup: {
              status: "required",
              verification: { active: true },
            },
            unique: true,
            verification_method: "otp",
          },
          username: {
            identifier: { active: false },
            validation: {
              min_length: 1,
              max_length: 15,
              allowed_types: { email: false, phone_number: false },
            },
          },
        },
        password_complexity_options: { min_length: 12 },
        password_dictionary: { dictionary: ["example"], enable: true },
        password_history: { enable: true, size: 5 },
        password_no_personal_info: { enable: true },
        validation: { username: { min: 1, max: 15 } },
        brute_force_protection: true,
        strategy_version: 2,
        requires_username: false,
        disable_signup: false,
      },
      "database_12345678",
    );

    expect(terraform).toContain("enabled_database_customization = false");
    expect(terraform).toContain(
      'custom_scripts = { "login" = "function login() {}" }',
    );
    expect(terraform).toContain('password_policy = "good"');
    expect(terraform).toContain("authentication_methods {");
    expect(terraform).toContain('api_behavior = "allow"');
    expect(terraform).toContain('verification_method = "otp"');
    expect(terraform).toContain("return_enroll_settings = true");
    expect(terraform).toContain("size = 5");
    expect(terraform).toContain(
      "configuration = data.auth0_connection.database_12345678.options[0].configuration",
    );
    expect(terraform).not.toContain("do-not-embed");
  });

  it("references sensitive nested values instead of embedding them", () => {
    const terraform = renderCompleteConnectionOptions(
      {
        gateway_authentication: {
          method: "bearer",
          secret: "do-not-embed",
        },
      },
      "database_12345678",
    );

    expect(terraform).toContain(
      "secret = data.auth0_connection.database_12345678.options[0].gateway_authentication[0].secret",
    );
    expect(terraform).not.toContain("do-not-embed");
  });

  it("fails closed for unknown root or nested provider fields", () => {
    expect(() =>
      renderCompleteConnectionOptions(
        { future_option: true },
        "database_12345678",
      ),
    ).toThrow(
      'has no schema for connection option "options.future_option"',
    );
    expect(() =>
      renderCompleteConnectionOptions(
        { mfa: { future_option: true } },
        "database_12345678",
      ),
    ).toThrow(
      'has no schema for connection option "options.mfa.future_option"',
    );
  });
});

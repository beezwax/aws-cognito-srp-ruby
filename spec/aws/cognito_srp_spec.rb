# frozen_string_literal: true

require "aws-cognito-srp"

RSpec.describe Aws::CognitoSrp do
  describe "#authenticate" do
    it "peforms the SRP auth flow and returns the tokens" do
      client = Aws::CognitoIdentityProvider::Client.new(
        region: "us-west-2",
        validate_params: false,
        stub_responses: {
          initiate_auth: {
            challenge_name: 'PASSWORD_VERIFIER',
            challenge_parameters: {
              "USER_ID_FOR_SRP" => "DUMMY_USER_ID_FOR_SRP",
              "SALT" => "DUMMY_SALT",
              "SRP_B" => "ABC123",
              "SECRET_BLOCK" => Base64.strict_encode64("DUMMY_SECRET_BLOCK"),
            },
          },

          respond_to_auth_challenge: {
            authentication_result: {
              id_token: 'dummy_id_token',
              access_token: 'dummy_access_token',
              refresh_token: 'dummy_refresh_token',
            }
          }
        }
      )

      aws_srp = Aws::CognitoSrp.new(
        username:   "username",
        password:   "password",
        pool_id:    "us-west-2_NqkuZcXQY",
        client_id:  "4l9rvl4mv5es1eep1qe97cautn",
        aws_client: client
      )

      tokens = aws_srp.authenticate

      expect(tokens.id_token).to eq('dummy_id_token')
      expect(tokens.access_token).to eq('dummy_access_token')
      expect(tokens.refresh_token).to eq('dummy_refresh_token')

      expect(client.api_requests.first).to include(
        operation_name: :initiate_auth,
        params: hash_including(
          auth_flow: "USER_SRP_AUTH",
          auth_parameters: hash_including(
            "USERNAME" => "username",
            "SRP_A" => a_string_matching(/[0-9a-f]+/),
          )
        )
      )

      # Matches a non-empty Base64 string
      b64_re = %r<^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$>

      expect(client.api_requests[1]).to include(
        operation_name: :respond_to_auth_challenge,
        params: hash_including(
          challenge_name: "PASSWORD_VERIFIER",
          challenge_responses: hash_including(
            "TIMESTAMP" => a_string_matching(/^[A-Z][a-z]{2} [A-Z][a-z]{2} \d\d? \d\d:\d\d:\d\d UTC \d{4,}$/),
            "USERNAME" => "DUMMY_USER_ID_FOR_SRP",
            "PASSWORD_CLAIM_SECRET_BLOCK" => a_string_matching(b64_re),
            "PASSWORD_CLAIM_SIGNATURE" => a_string_matching(b64_re)
          )
        )
      )
    end
  end
end

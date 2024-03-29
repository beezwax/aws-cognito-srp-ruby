# frozen_string_literal: true

require "aws-cognito-srp"

RSpec.describe Aws::CognitoSrp do
  # Matches a non-empty Base64 string
  let(:b64_re) { %r<^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$> }

  describe "#authenticate" do
    let(:respond_to_auth_challenge_response) do
      {
        authentication_result: {
          id_token: 'dummy_id_token',
          access_token: 'dummy_access_token',
          refresh_token: 'dummy_refresh_token'
        }
      }
    end

    let(:client) do
      Aws::CognitoIdentityProvider::Client.new(
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

          respond_to_auth_challenge: respond_to_auth_challenge_response
        }
      )
    end

    context 'when client_secret is not provided' do
      let(:aws_srp) do
        Aws::CognitoSrp.new(
          username:   "username",
          password:   "password",
          pool_id:    "us-west-2_NqkuZcXQY",
          client_id:  "4l9rvl4mv5es1eep1qe97cautn",
          aws_client: client
        )
      end

      it "peforms the SRP auth flow and returns the tokens" do
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

    context 'when client_secret is provided' do
      let(:aws_srp) do
        Aws::CognitoSrp.new(
          username:      "username",
          password:      "password",
          pool_id:       "us-west-2_NqkuZcXQY",
          client_id:     "4l9rvl4mv5es1eep1qe97cautn",
          aws_client:    client,
          client_secret: "client-secret"
        )
      end

      it "peforms the SRP auth flow and returns the tokens" do
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
              "SECRET_HASH" => a_string_matching(b64_re),
            )
          )
        )

        expect(client.api_requests[1]).to include(
          operation_name: :respond_to_auth_challenge,
          params: hash_including(
            challenge_name: "PASSWORD_VERIFIER",
            challenge_responses: hash_including(
              "TIMESTAMP" => a_string_matching(/^[A-Z][a-z]{2} [A-Z][a-z]{2} \d\d? \d\d:\d\d:\d\d UTC \d{4,}$/),
              "USERNAME" => "DUMMY_USER_ID_FOR_SRP",
              "PASSWORD_CLAIM_SECRET_BLOCK" => a_string_matching(b64_re),
              "PASSWORD_CLAIM_SIGNATURE" => a_string_matching(b64_re),
              "SECRET_HASH" => a_string_matching(b64_re),
            )
          )
        )
      end
    end

    context 'when respond_to_auth_challenge returns MFA challenge' do
      let (:respond_to_auth_challenge_response) do
        {
          challenge_name: 'SOFTWARE_TOKEN_MFA',
          session: 'dummy_session'
        }
      end

      let(:aws_srp) do
        Aws::CognitoSrp.new(
          username:   "username",
          password:   "password",
          pool_id:    "us-west-2_NqkuZcXQY",
          client_id:  "4l9rvl4mv5es1eep1qe97cautn",
          aws_client: client
        )
      end

      it "returns the challenge name and session" do
        response = aws_srp.authenticate
        expect(response.challenge_name).to eq('SOFTWARE_TOKEN_MFA')
        expect(response.session).to eq('dummy_session')
        expect(response.mfa_challenge?).to eq(true)
        expect(response.software_token_mfa?).to eq(true)
        expect(response.sms_mfa?).to eq(false)
      end
    end
  end

  describe "#refresh_tokens" do
    let(:client) do
      Aws::CognitoIdentityProvider::Client.new(
        region: "us-west-2",
        validate_params: false,
        stub_responses: {
          initiate_auth: {
            authentication_result: {
              id_token: 'dummy_id_token',
              access_token: 'dummy_access_token',
              refresh_token: 'dummy_refresh_token',
            }
          }
        }
      )
    end

    context 'when client_secret is not provided' do
      let(:aws_srp) do
        Aws::CognitoSrp.new(
          username:   "username",
          password:   "password",
          pool_id:    "us-west-2_NqkuZcXQY",
          client_id:  "4l9rvl4mv5es1eep1qe97cautn",
          aws_client: client
        )
      end

      it "peforms a refresh token flow and returns the new tokens" do
        tokens = aws_srp.refresh_tokens("dummy_refresh_token")

        expect(tokens.id_token).to eq('dummy_id_token')
        expect(tokens.access_token).to eq('dummy_access_token')
        expect(tokens.refresh_token).to eq('dummy_refresh_token')

        expect(client.api_requests.first).to include(
          operation_name: :initiate_auth,
          params: hash_including(
            auth_flow: "REFRESH_TOKEN",
            auth_parameters: hash_including(
              "REFRESH_TOKEN" => "dummy_refresh_token"
            )
          )
        )
      end
    end

    context 'when client_secret is provided' do
      let(:aws_srp) do
        Aws::CognitoSrp.new(
          username:      "username",
          password:      "password",
          pool_id:       "us-west-2_NqkuZcXQY",
          client_id:     "4l9rvl4mv5es1eep1qe97cautn",
          aws_client:    client,
          client_secret: "client-secret"
        )
      end

      it "peforms a refresh token flow and returns the new tokens" do
        tokens = aws_srp.refresh_tokens("dummy_refresh_token", user_id_for_srp: "dummy_user_id_for_srp")

        expect(tokens.id_token).to eq('dummy_id_token')
        expect(tokens.access_token).to eq('dummy_access_token')
        expect(tokens.refresh_token).to eq('dummy_refresh_token')

        expect(client.api_requests.first).to include(
          operation_name: :initiate_auth,
          params: hash_including(
            auth_flow: "REFRESH_TOKEN",
            auth_parameters: hash_including(
              "REFRESH_TOKEN" => "dummy_refresh_token",
              "SECRET_HASH" => a_string_matching(b64_re)
            )
          )
        )
      end
    end
  end

  describe "#user_id_for_srp" do
    let(:client) do
      Aws::CognitoIdentityProvider::Client.new(
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
          }
        }
      )
    end

    let(:aws_srp) do
      Aws::CognitoSrp.new(
        username:   "username",
        password:   "password",
        pool_id:    "us-west-2_NqkuZcXQY",
        client_id:  "4l9rvl4mv5es1eep1qe97cautn",
        aws_client: client
      )
    end

    it "returns user_id_for_srp of response of initiate_auth" do
      aws_srp.authenticate
      expect(aws_srp.user_id_for_srp).to eq("DUMMY_USER_ID_FOR_SRP")
    end
  end

  describe "#refresh" do
    it "is an alias for #refresh_tokens" do
      aws_srp = Aws::CognitoSrp.new(
        username:   "username",
        password:   "password",
        pool_id:    "us-west-2_NqkuZcXQY",
        client_id:  "4l9rvl4mv5es1eep1qe97cautn",
        aws_client: Aws::CognitoIdentityProvider::Client.new(region: "us-west-2")
      )

      expect(aws_srp.method(:refresh)).to eq(aws_srp.method(:refresh_tokens))
    end
  end

  describe "#respond_to_mfa_challenge" do
    let(:client) do
      Aws::CognitoIdentityProvider::Client.new(
        region: "us-west-2",
        validate_params: false,
        stub_responses: {
          respond_to_auth_challenge: {
            authentication_result: {
              id_token: 'dummy_id_token',
              access_token: 'dummy_access_token',
              refresh_token: 'dummy_refresh_token',
            }
          }
        }
      )
    end

    let(:aws_srp) do
      Aws::CognitoSrp.new(
        username:   "username",
        password:   "password",
        pool_id:    "us-west-2_NqkuZcXQY",
        client_id:  "4l9rvl4mv5es1eep1qe97cautn",
        aws_client: client
      )
    end

    it "validates required keyword arguments raising an exception" do
      expect { aws_srp.respond_to_mfa_challenge('dummy_user_code') }.to raise_error(ArgumentError)
      expect { aws_srp.respond_to_mfa_challenge('dummy_user_code', session: 'dummy_session') }.to raise_error(ArgumentError)
      expect { aws_srp.respond_to_mfa_challenge('dummy_user_code', challenge_name: 'SOFTWARE_TOKEN_MFA') }.to raise_error(ArgumentError)
    end

    it "calls respond_to_auth_challenge api with access_token and settings" do
      response = aws_srp.respond_to_mfa_challenge(
        'dummy_user_code',
        challenge_name: 'SOFTWARE_TOKEN_MFA',
        session: 'dummy_session'
      )

      expect(client.api_requests[0]).to include(
        operation_name: :respond_to_auth_challenge,
        params: hash_including(
          challenge_name: 'SOFTWARE_TOKEN_MFA',
          session: 'dummy_session',
          challenge_responses: {
            "SOFTWARE_TOKEN_MFA_CODE" => 'dummy_user_code'
          }
        )
      )
      expect(response.id_token).to eq('dummy_id_token')
      expect(response.access_token).to eq('dummy_access_token')
      expect(response.refresh_token).to eq('dummy_refresh_token')
    end

    it "extracts challenge_name and session from auth_response object if given" do
      response = aws_srp.respond_to_mfa_challenge(
        'dummy_user_code',
        auth_response: double('ChallengeResponse',
                              challenge_name: 'SOFTWARE_TOKEN_MFA',
                              session: 'dummy_session')
      )

      expect(client.api_requests[0]).to include(
        operation_name: :respond_to_auth_challenge,
        params: hash_including(
          challenge_name: 'SOFTWARE_TOKEN_MFA',
          session: 'dummy_session',
          challenge_responses: {
            "SOFTWARE_TOKEN_MFA_CODE" => 'dummy_user_code'
          }
        )
      )
    end
  end
end

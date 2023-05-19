# frozen_string_literal: true

require "aws-sdk-cognitoidentityprovider"

require "openssl"
require "digest"
require "securerandom"
require "base64"

require "aws/cognito_srp/version"
require "aws/cognito_srp/errors"

if Gem::Version.new(RUBY_VERSION) < Gem::Version.new("2.5")
  module IntegerWithPow
    refine Integer do
      # Integer#pow was introduced in Ruby 2.5
      # Use OpenSSL's modular exponentiation in older Rubies
      def pow(b, m)
        self.to_bn.mod_exp(b, m).to_i
      end
    end
  end

  using IntegerWithPow
end

module Aws
  # Client for AWS Cognito Identity Provider using Secure Remote Password (SRP).
  #
  # Borrowed from:
  # https://gist.github.com/jviney/5fd0fab96cd70d5d46853f052be4744c
  #
  # This code is a direct translation of the Python version found here:
  # https://github.com/capless/warrant/blob/ff2e4793d8479e770f2461ef7cbc0c15ee784395/warrant/aws_srp.py
  #
  # Example usage:
  #
  #   aws_srp = Aws::CognitoSrp.new(
  #     username: "username",
  #     password: "password",
  #     pool_id: "pool-id",
  #     client_id: "client-id",
  #     aws_client: Aws::CognitoIdentityProvider::Client.new(region: "us-west-2")
  #   )
  #
  #   aws_srp.authenticate
  #
  class CognitoSrp
    NEW_PASSWORD_REQUIRED = "NEW_PASSWORD_REQUIRED"
    PASSWORD_VERIFIER = "PASSWORD_VERIFIER"
    REFRESH_TOKEN = "REFRESH_TOKEN"
    USER_SRP_AUTH = "USER_SRP_AUTH"
    SOFTWARE_TOKEN_MFA = "SOFTWARE_TOKEN_MFA"
    SMS_MFA = "SMS_MFA"

    N_HEX = %w(
      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
      8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
      302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
      A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
      49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
      FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
      180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
      3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
      04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
      B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
      1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
      E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
    ).join.freeze

    G_HEX = '2'

    INFO_BITS = 'Caldera Derived Key'

    attr_reader :user_id_for_srp

    def initialize(username:, password:, pool_id:, client_id:, aws_client:, client_secret: nil)
      @username = username
      @password = password
      @pool_id = pool_id
      @client_id = client_id
      @aws_client = aws_client
      @client_secret = client_secret

      @big_n = hex_to_long(N_HEX)
      @g = hex_to_long(G_HEX)
      @k = hex_to_long(hex_hash("00#{N_HEX}0#{G_HEX}"))
      @small_a_value = generate_random_small_a
      @large_a_value = calculate_a
    end

    def authenticate
      auth_parameters = {
        USERNAME: @username,
        SRP_A: long_to_hex(@large_a_value),
        SECRET_HASH: @client_secret && secret_hash(@username)
      }.compact

      init_auth_response = @aws_client.initiate_auth(
        client_id: @client_id,
        auth_flow: USER_SRP_AUTH,
        auth_parameters: auth_parameters
      )

      unless init_auth_response.challenge_name == PASSWORD_VERIFIER
        raise UnexpectedChallenge, "Expected Cognito to respond with a #{PASSWORD_VERIFIER} challenge, got #{init_auth_response.challenge_name} instead"
      end

      challenge_response = process_challenge(init_auth_response.challenge_parameters)
      hash = @client_secret && secret_hash(@user_id_for_srp)

      params = {
        client_id: @client_id,
        challenge_name: PASSWORD_VERIFIER,
        challenge_responses: challenge_response.merge(SECRET_HASH: hash).compact
      }

      auth_response = @aws_client.respond_to_auth_challenge(params)

      if auth_response.challenge_name == SOFTWARE_TOKEN_MFA || auth_response.challenge_name == SMS_MFA
        return auth_response
      end

      if auth_response.challenge_name == NEW_PASSWORD_REQUIRED
        raise NewPasswordRequired, "Cognito responded to password verifier with a #{NEW_PASSWORD_REQUIRED} challenge"
      end

      auth_response.authentication_result
    end

    def refresh_tokens(refresh_token, user_id_for_srp: @user_id_for_srp)
      auth_parameters = {
        REFRESH_TOKEN: refresh_token,
        SECRET_HASH: @client_secret && secret_hash(user_id_for_srp)
      }.compact

      resp = @aws_client.initiate_auth(
        client_id: @client_id,
        auth_flow: REFRESH_TOKEN,
        auth_parameters: auth_parameters
      )

      resp.authentication_result
    end
    alias_method :refresh, :refresh_tokens

    def respond_to_auth_challenge_mfa(challenge_name, session, user_code, user_id_for_srp: @user_id_for_srp)
      hash = @client_secret && secret_hash(user_id_for_srp)

      challenge_responses = {
        USERNAME: user_id_for_srp,
        SECRET_HASH: hash
      }
      if challenge_name == SOFTWARE_TOKEN_MFA
        challenge_responses[:SOFTWARE_TOKEN_MFA_CODE] = user_code
      elsif challenge_name == SMS_MFA
        challenge_responses[:SMS_MFA_CODE] = user_code
      end

      params = {
        challenge_name: challenge_name,
        session: session,
        client_id: @client_id,
        challenge_responses: challenge_responses.compact
      }.compact

      resp = @aws_client.respond_to_auth_challenge(params)
      resp.authentication_result
    end

    private

    def generate_random_small_a
      random_long_int = get_random(128)
      random_long_int % @big_n
    end

    def calculate_a
      big_a = @g.pow(@small_a_value, @big_n)
      raise ValueError, "Safety check for A failed" if big_a % @big_n == 0
      big_a
    end

    def get_password_authentication_key(username, password, server_b_value, salt)
      u_value = calculate_u(@large_a_value, server_b_value)

      raise ValueError, "U cannot be zero" if u_value == 0

      username_password = "#{@pool_id.split("_")[1]}#{username}:#{password}"
      username_password_hash = hash_sha256(username_password)

      x_value = hex_to_long(hex_hash(pad_hex(salt) + username_password_hash))
      g_mod_pow_xn = @g.pow(x_value, @big_n)
      int_value2 = server_b_value - @k * g_mod_pow_xn
      s_value = int_value2.pow(@small_a_value + u_value * x_value, @big_n)
      compute_hkdf(hex_to_bytes(pad_hex(s_value)), hex_to_bytes(pad_hex(long_to_hex(u_value))))
    end

    def process_challenge(challenge_parameters)
      @user_id_for_srp = challenge_parameters.fetch("USER_ID_FOR_SRP")
      salt_hex = challenge_parameters.fetch("SALT")
      srp_b_hex = challenge_parameters.fetch("SRP_B")
      secret_block_b64 = challenge_parameters.fetch("SECRET_BLOCK")

      timestamp = ::Time.now.utc.strftime("%a %b %-d %H:%M:%S %Z %Y")

      hkdf = get_password_authentication_key(@user_id_for_srp, @password, srp_b_hex.to_i(16), salt_hex)
      secret_block_bytes = ::Base64.strict_decode64(secret_block_b64)
      msg = @pool_id.split("_")[1] + @user_id_for_srp + secret_block_bytes + timestamp
      hmac_digest = ::OpenSSL::HMAC.digest(::OpenSSL::Digest::SHA256.new, hkdf, msg)
      signature_string = ::Base64.strict_encode64(hmac_digest).force_encoding('utf-8')

      {
        TIMESTAMP: timestamp,
        USERNAME: @user_id_for_srp,
        PASSWORD_CLAIM_SECRET_BLOCK: secret_block_b64,
        PASSWORD_CLAIM_SIGNATURE: signature_string
      }
    end

    def hash_sha256(buf)
      ::Digest::SHA256.hexdigest(buf)
    end

    def hex_hash(hex_string)
      hash_sha256(hex_to_bytes(hex_string))
    end

    def hex_to_bytes(hex_string)
      [hex_string].pack('H*')
    end

    def bytes_to_hex(bytes)
      bytes.unpack1('H*')
    end

    def hex_to_long(hex_string)
      hex_string.to_i(16)
    end

    def long_to_hex(long_num)
      long_num.to_s(16)
    end

    def get_random(nbytes)
      hex_to_long(bytes_to_hex(::SecureRandom.gen_random(nbytes)))
    end

    def pad_hex(long_int)
      hash_str = long_int.is_a?(::String) ? long_int : long_to_hex(long_int)

      if hash_str.size % 2 == 1
        hash_str = "0#{hash_str}"
      elsif '89ABCDEFabcdef'.include?(hash_str[0])
        hash_str = "00#{hash_str}"
      end

      hash_str
    end

    def compute_hkdf(ikm, salt)
      prk = ::OpenSSL::HMAC.digest(::OpenSSL::Digest::SHA256.new, salt, ikm)
      info_bits_update = INFO_BITS + 1.chr.force_encoding('utf-8')
      hmac_hash = ::OpenSSL::HMAC.digest(::OpenSSL::Digest::SHA256.new, prk, info_bits_update)
      hmac_hash[0, 16]
    end

    def calculate_u(big_a, big_b)
      u_hex_hash = hex_hash(pad_hex(big_a) + pad_hex(big_b))
      hex_to_long(u_hex_hash)
    end

    def secret_hash(username)
      Base64.strict_encode64(OpenSSL::HMAC.digest('sha256', @client_secret, username + @client_id))
    end
  end
end

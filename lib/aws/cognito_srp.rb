# frozen_string_literal: true

require "aws-sdk-cognitoidentityprovider"
require "aws/cognito_srp/version"

require "openssl"
require "digest"

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
    USER_SRP_AUTH = "USER_SRP_AUTH"
    PASSWORD_VERIFIER = "PASSWORD_VERIFIER"
    NEW_PASSWORD_REQUIRED = "NEW_PASSWORD_REQUIRED"

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

    def initialize(username:, password:, pool_id:, client_id:, aws_client:)
      @username = username
      @password = password
      @pool_id = pool_id
      @client_id = client_id
      @aws_client = aws_client

      @big_n = hex_to_long(N_HEX)
      @g = hex_to_long(G_HEX)
      @k = hex_to_long(hex_hash("00#{N_HEX}0#{G_HEX}"))
      @small_a_value = generate_random_small_a
      @large_a_value = calculate_a
    end

    def authenticate
      init_auth_response = @aws_client.initiate_auth(
        client_id: @client_id,
        auth_flow: USER_SRP_AUTH,
        auth_parameters: {
          USERNAME: @username,
          SRP_A: long_to_hex(@large_a_value)
        }
      )

      raise unless init_auth_response.challenge_name == PASSWORD_VERIFIER

      challenge_response = process_challenge(init_auth_response.challenge_parameters)

      auth_response = @aws_client.respond_to_auth_challenge(
        client_id: @client_id,
        challenge_name: PASSWORD_VERIFIER,
        challenge_responses: challenge_response
      )

      raise "new password required" if auth_response.challenge_name == NEW_PASSWORD_REQUIRED

      auth_response.authentication_result
    end

    private

    def generate_random_small_a
      random_long_int = get_random(128)
      random_long_int % @big_n
    end

    def calculate_a
      big_a = @g.pow(@small_a_value, @big_n)
      if big_a % @big_n == 0
        raise "Safety check for A failed"
      end

      big_a
    end

    def get_password_authentication_key(username, password, server_b_value, salt)
      u_value = calculate_u(@large_a_value, server_b_value)
      if u_value == 0
        raise "U cannot be zero."
      end

      username_password = "#{@pool_id.split("_")[1]}#{username}:#{password}"
      username_password_hash = hash_sha256(username_password)

      x_value = hex_to_long(hex_hash(pad_hex(salt) + username_password_hash))
      g_mod_pow_xn = @g.pow(x_value, @big_n)
      int_value2 = server_b_value - @k * g_mod_pow_xn
      s_value = int_value2.pow(@small_a_value + u_value * x_value, @big_n)
      hkdf = compute_hkdf(hex_to_bytes(pad_hex(s_value)), hex_to_bytes(pad_hex(long_to_hex(u_value))))
      hkdf
    end

    def process_challenge(challenge_parameters)
      user_id_for_srp = challenge_parameters.fetch("USER_ID_FOR_SRP")
      salt_hex = challenge_parameters.fetch("SALT")
      srp_b_hex = challenge_parameters.fetch("SRP_B")
      secret_block_b64 = challenge_parameters.fetch("SECRET_BLOCK")

      timestamp = Time.now.utc.strftime("%a %b %-d %H:%M:%S %Z %Y")

      hkdf = get_password_authentication_key(user_id_for_srp, @password, srp_b_hex.to_i(16), salt_hex)
      secret_block_bytes = Base64.strict_decode64(secret_block_b64)
      msg = @pool_id.split("_")[1] + user_id_for_srp + secret_block_bytes + timestamp
      hmac_digest = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), hkdf, msg)
      signature_string = Base64.strict_encode64(hmac_digest).force_encoding('utf-8')

      {
        "TIMESTAMP" => timestamp,
        "USERNAME" => user_id_for_srp,
        "PASSWORD_CLAIM_SECRET_BLOCK" => secret_block_b64,
        "PASSWORD_CLAIM_SIGNATURE" => signature_string
      }
    end

    def hash_sha256(buf)
      Digest::SHA256.hexdigest(buf)
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
      random_hex = bytes_to_hex(SecureRandom.bytes(nbytes))
      hex_to_long(random_hex)
    end

    def pad_hex(long_int)
      hash_str = if long_int.is_a?(String)
        long_int
      else
        long_to_hex(long_int)
      end

      if hash_str.size % 2 == 1
        hash_str = "0#{hash_str}"
      elsif '89ABCDEFabcdef'.include?(hash_str[0])
        hash_str = "00#{hash_str}"
      end

      hash_str
    end

    def compute_hkdf(ikm, salt)
      prk = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), salt, ikm)
      info_bits_update = INFO_BITS + 1.chr.force_encoding('utf-8')
      hmac_hash = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), prk, info_bits_update)
      hmac_hash[0, 16]
    end

    def calculate_u(big_a, big_b)
      u_hex_hash = hex_hash(pad_hex(big_a) + pad_hex(big_b))
      hex_to_long(u_hex_hash)
    end
  end
end


# frozen_string_literal: true

require "aws/cognito_srp/errors"

module Aws
  class CognitoSrp
    module ChallengeResponseHelper
      def mfa_challenge?
        software_token_mfa? || sms_mfa?
      end

      def software_token_mfa?
        challenge_name == SOFTWARE_TOKEN_MFA
      end

      def sms_mfa?
        challenge_name == SMS_MFA
      end
    end
  end
end

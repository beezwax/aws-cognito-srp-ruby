# frozen_string_literal: true

require "aws/cognito_srp/errors"

module Aws
  class CognitoSrp
    class Error < ::RuntimeError; end
    class UnexpectedChallenge < Error; end
    class NewPasswordRequired < Error; end
    class ValueError < Error; end
  end
end

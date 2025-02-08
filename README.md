# Aws::CognitoSrp for Ruby

[![Gem Version](https://badge.fury.io/rb/aws-cognito-srp.svg?style=flat)](https://rubygems.org/gems/aws-cognito-srp)
![CI](https://github.com/beezwax/aws-cognito-srp-ruby/workflows/CI/badge.svg)

An unofficial Ruby library implementing
[AWS Cognito's SRP authentication flow](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html#Using-SRP-password-verification-in-custom-authentication-flow).

[Originally
translated](https://gist.github.com/jviney/5fd0fab96cd70d5d46853f052be4744c#file-aws_cognito_srp-rb-L4)
from Python's [Warrant](https://github.com/capless/warrant) by Jonathan Viney,
packaged into this gem by [Beezwax](https://beezwax.net).

## Installation

In your Gemfile:

```ruby
gem 'aws-cognito-srp'
```

## Usage

```ruby
require "aws-cognito-srp"

aws_srp = Aws::CognitoSrp.new(
  username:      "username",
  password:      "password",
  pool_id:       "pool-id",
  client_id:     "client-id",
  client_secret: "client-secret", # Optional
  aws_client:    Aws::CognitoIdentityProvider::Client.new(region: "aws-region")
)

resp = aws_srp.authenticate

# Read tokens
resp.id_token
resp.access_token
resp.refresh_token

# A few hours later ... ⌛️

new_tokens = aws_srp.refresh_tokens(resp.refresh_token)
```

### `USER_ID_FOR_SRP`

In case you need access to the `USER_ID_FOR_SRP` value from the auth response,
you can do so by calling `aws_srp.user_id_for_srp` *after* the initial auth
(`aws_srp` being the same as in the code example above).

If you're using a `client_secret` and calling `#refresh_tokens` in a different
instance than the one that performed the initial call to `#authenticate` you
will have to pass the `USER_ID_FOR_SRP` value as a keyword argument:

```ruby
new_tokens = aws_srp.refresh_token(resp.refresh_token,
                                   user_id_for_srp: your_user_id_for_srp)
```

### MFA (multi-factor authentication)

If you're using MFA you should check for the challenge after calling
`#authenticate` and respond accordingly with `#respond_to_mfa_challenge`.

```ruby
resp = aws_srp.authenticate

if resp.respond_to?(:challenge_name) && resp.mfa_challenge?
  user_code = get.chomp # Get MFA code from user

  resp = aws_srp.respond_to_mfa_challenge(
    user_code,
    auth_response: resp
  )
end

resp.id_token
resp.access_token
resp.refresh_token
```

Note that when `#authenticate` results in a successful authentication it
returns a `AuthenticationResultType`
([AWS SDK docs](https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/CognitoIdentityProvider/Types/AuthenticationResultType.html)),
i.e. an object that responds to `#id_token`, `#access_token`, etc.

However, when a MFA challenge step occurs, `#authenticate` instead returns a
`RespondToAuthChallengeResponse` ([AWS SDK docs](https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/CognitoIdentityProvider/Types/RespondToAuthChallengeResponse.html#authentication_result-instance_method)),
which you can check for with `.respond_to?(:challenge_name)` as in the above
example. The `RespondToAuthChallengeResponse` object will be extended with the
convenience methods `#mfa_challenge?`, `#software_token_mfa?` and `#sms_mfa?`.

The `#respond_to_mfa_challenge` method can be called with the following
signatures:

```
#respond_to_mfa_challenge(user_code, auth_response: [, user_id_for_srp:])
#respond_to_mfa_challenge(user_code, challenge_name:, session: [, user_id_for_srp:])
```

## Supported rubies

This gem is tested against and supports Ruby 2.7 through 3.3, JRuby and
TruffleRuby.

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can
also run `bin/console` for an interactive prompt that will allow you to
experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To
release a new version, update the version number in `version.rb`, and then run
`bundle exec rake release`, which will create a git tag for the version, push
git commits and the created tag, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/beezwax/aws-cognito-srp-ruby

## Disclaimer

This project is not sponsored by or otherwise affiliated with Amazon Web
Services, Inc., an Amazon.com, Inc. subsidiary. AWS and Amazon Cognito are
trademarks of Amazon.com, Inc., or its affiliates in the United States and/or
other countries.

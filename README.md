# Aws::CognitoSrp for Ruby

[![Gem Version](https://badge.fury.io/rb/aws-cognito-srp.svg?style=flat)](https://rubygems.org/gems/aws-cognito-srp)
![CI](https://github.com/beezwax/aws-cognito-srp-ruby/workflows/CI/badge.svg)

An unofficial Ruby library implementing
[AWS Cognito's SRP authentication flow](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html#Using-SRP-password-verification-in-custom-authentication-flow).

[Originally
translated](https://gist.github.com/jviney/5fd0fab96cd70d5d46853f052be4744c#file-aws_cognito_srp-rb-L4)
from Python's [Warrant](https://github.com/capless/warrant) by Jonathan Viney,
packaged into this gem by Pedro Carbajal.

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

### MFA

You can enable MFA.

```ruby
resp = aws_srp.associate_software_token(access_token)
puts resp.secret_code

# setup MFA app with `resp.secret_code` and input code showed in your MFA app.
user_code = gets.chomp

aws_srp.verify_software_token(access_token, user_code)

aws_srp.set_user_mfa_preference(
  access_token,
  software_token_mfa_settings: {
    enabled: true,
    preferred_mfa: true
  }
)
```

Authentication with MFA.

```ruby
resp = aws_srp.authenticate

if resp.respond_to?(:challenge_name) && resp.challenge_name == 'SOFTWARE_TOKEN_MFA'

  user_code = get.chomp # input MFA code

  resp = aws_srp.respond_to_auth_challenge_mfa(
    resp.challenge_name,
    resp.session,
    user_code
  )
end

resp.id_token
resp.access_token
resp.refresh_token
```

You can disable MFA.

```ruby
aws_srp.set_user_mfa_preference(
  access_token,
  software_token_mfa_settings: {
    enabled: false,
    preferred_mfa: false
  }
)
```

## Supported rubies

This gem is tested against and supports Ruby 2.4 through 3.2, JRuby and
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

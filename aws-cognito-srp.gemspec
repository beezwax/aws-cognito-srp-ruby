# frozen_string_literal: true

require_relative "lib/aws/cognito_srp/version"

Gem::Specification.new do |spec|
  spec.name          = "aws-cognito-srp"
  spec.version       = Aws::CognitoSrp::VERSION
  spec.authors       = ["Jonathan Viney", "Pedro Carbajal", "The Warrant developers"]
  spec.email         = ["pedro_c@beezwax.net"]

  spec.summary       = "AWS Cognito SRP auth for Ruby"
  spec.description   = "Unofficial Ruby library implementing AWS Cognito's SRP authentication flow"
  spec.homepage      = "https://github.com/beezwax/aws-cognito-srp-ruby"
  spec.license       = "MIT"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{\A(?:test|spec|features)/}) }
  end
  spec.require_paths = ["lib"]

  spec.required_ruby_version = '>= 2.7.0'

  spec.add_dependency "aws-sdk-cognitoidentityprovider"
  spec.add_dependency "base64"

  spec.add_development_dependency "bundler", "~> 2.2"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "nokogiri", "~> 1.9"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "pry"

  # For more information and examples about making a new gem, checkout our
  # guide at: https://bundler.io/guides/creating_gem.html
end

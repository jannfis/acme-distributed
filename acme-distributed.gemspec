lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'acme/distributed/version'

Gem::Specification.new do |spec|
  spec.name          = 'acme-distributed'
  spec.version       = Acme::Distributed::VERSION
  spec.author        = ['jann@mistrust.net']
  spec.email         = ['jann@mistrust.net']
  spec.summary       = 'Letsencrypt command line client'
  spec.homepage      = 'http://github.com/jannfis/acme-distributed'
  spec.license       = 'Unlicense'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.5.0'

  spec.add_development_dependency 'bundler', '~> 1.6', '>= 1.6.9'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.3', '>= 3.3.0'

  spec.add_runtime_dependency 'acme-client', '~> 2.0', '>= 2.0.1'
  spec.add_runtime_dependency 'net-ssh', '~> 5.0', '>= 5.0.0'
  spec.add_runtime_dependency 'openssl', '~> 2.0', '>= 2.0.0'
  spec.add_runtime_dependency 'logger', '~> 1.3', '>= 1.3.0'

end

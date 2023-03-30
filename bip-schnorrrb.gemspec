
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "schnorr/version"

Gem::Specification.new do |spec|
  spec.name          = "bip-schnorr"
  spec.version       = Schnorr::VERSION
  spec.authors       = ["azuchi"]
  spec.email         = ["azuchi@chaintope.com"]

  spec.summary       = %q{The ruby implementation of bip-schnorr.}
  spec.description   = %q{The ruby implementation of bip-schnorr.}
  spec.homepage      = "https://github.com/chaintope/bip-schnorrrb"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.add_runtime_dependency "ecdsa_ext", "~> 0.5.0"

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake", ">= 12.3.3"
  spec.add_development_dependency "rspec", "~> 3.0"
end

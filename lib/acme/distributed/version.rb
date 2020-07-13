module Acme
  module Distributed
    VERSION = "0.4.0-MASTER".freeze

    # Return extended version info
    def self.versioninfo
      version = "Acme::Distributed version {{ version }} (using acme-client v{{ acme_version }})"
      Acme::Distributed::Util.expand_variables(version, { version: VERSION, acme_version: Acme::Client::VERSION }, { remove_unknown: false })
    end

    # Return copyright information
    def self.copyright
      "This software is put into the Public Domain under the terms of Unlicense\n" +
      "Please refer to https://github.com/jannfis/acme-distributed and https://www.unlicense.org for more details."
    end

  end
end

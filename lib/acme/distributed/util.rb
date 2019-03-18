require 'openssl'
require 'acme/distributed/errors'

# Utility functions for Acme::Distributed
#
module Acme::Distributed::Util

  # Default options for expand_variables()
  DEFAULT_VARIABLE_OPTIONS = {
    remove_unknown: true,
  }

  # Expand all variables in a string, according to the varset given. varset is
  # a simple Hash object, whose keys are the variable names to replace and the
  # values are the corresponding values the variable is replaced with.
  #
  # If given, the options hash further defines the behaviour of the replacement
  # actions.
  #
  # @param string [String] The original string
  # @param varset [Hash] Hash containing variable-value mappings for variables to be interpolated
  # @param options [Hash] Hash containing replacement options
  # @return [String] A copy of string with all variables being replaced
  #
  def self.expand_variables(string, varset, options = {})
    raise TypeError, "varset must be Hash" if not varset.is_a?(Hash)
    raise TypeError, "options must be Hash" if not options.is_a?(Hash)
    result = string.dup
    opts = DEFAULT_VARIABLE_OPTIONS.merge(options)
    if string =~ /\{\{\ *[a-zA-Z0-9\_]+\ *\}\}/
      varset.keys.each do |var_name|
        while result.sub!(/\{\{\ *#{var_name}\ *\}\}/, varset[var_name]); end
      end
      if opts[:remove_unknown]
        while result.sub!(/\{\{\ *[a-zA-Z0-9\_]+\ *\}\}/, ''); end
      end
    end
    result
  end

  # Generate a private RSA key and stores it at path specified. The path where
  # the key should be stored must exist and be writable for the current user.
  # 
  # @throws [Acme::Distributed::ConfigurationError] Path does not exist or is not writable
  # @return nothing
  #
  def self.generate_private_key!(path, umask = 0077)
    basepath = File.dirname(path)
    if not File.writable?(basepath)
      raise Acme::Distributed::ConfigurationError, "Path #{basepath} does either not exist or is not writeable."
    end
    key = OpenSSL::PKey::RSA.new(4096)
    orig_umask = File.umask(umask)
    File.write(path, key, 0, mode: "w")
    File.umask(orig_umask)
  end
end

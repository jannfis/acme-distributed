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
end

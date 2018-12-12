require 'acme/distributed/configuration_error'

# Acme::Distributed::Endpoint
#
# This class represents an ACME endpoint configuration.
#
class Acme::Distributed::Endpoint
  REQUIRED_CONFIG_KEYS = [ "url", "private_key", "email_addr" ]

  def initialize(name, options)
    @name = name
    @options = options
    validate!
  end

  def name
    @name
  end

  def uri
    @options['url']
  end

  def uri=(value)
    @options['url'] = value
  end

  def url
    self.uri
  end

  def url=(value)
    self.uri = value
  end

  def private_key
    @options['private_key']
  end

  def private_key=(value)
    @options['private_key'] = value
  end

  def email_address
    @options['email_address']
  end

  def email_address=(value)
    @options['email_address'] = value
  end

  # Check whether the endpoint's private key exist and is readable
  def key_exist?
    File.exist?(self.private_key) && File.readable?(self.private_key)
  end

  private

  def validate!
    if not @options.is_a?(Hash)
      raise Acme::Distributed::ConfigurationError, "Configuration for endpoint '#{@name}' is not a hash."
    end

    REQUIRED_CONFIG_KEYS.each do |key|
      if not @options[key]
        raise Acme::Distributed::ConfigurationError, "Incomplete configuration for endpoint '#{@name}': Property '#{key}' is missing"
      end
    end
  end

end

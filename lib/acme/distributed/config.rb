require 'yaml'

require 'acme/distributed/logger'

require 'acme/distributed/endpoint'
require 'acme/distributed/certificate'

require 'acme/distributed/connector'

class Acme::Distributed::Config

  # List of required keys in configuration YAML
  #
  REQUIRED_CONFIG_KEYS = [ "endpoints", "certificates", "connectors" ]

  # List of valid keys for defaults section 
  #
  VALID_DEFAULT_KEYS = {
    "endpoint" => String,
    "renew_days" => Integer,
    "connector_type" => String
  }

  # List of valid challenge types and their implementation classes.
  #
  VALID_CHALLENGE_TYPES = {
    "ssh_http_file" => Acme::Distributed::Connector::SshHttpFile
  }

  # Load configuration from file
  #
  def initialize(file, options = {})
    @logger = Acme::Distributed::Logger.new
    @filename = file

    @logger.info("Loading configuration from file #{@filename}")

    @options = options || {}
    @defaults = {}
    @config = {}

    begin
      yaml = YAML.load(File.open(file).read)
    rescue StandardError => msg
      raise Acme::Distributed::ConfigurationError, msg
    rescue RuntimeError => msg
      raise Acme::Distributed::ConfigurationError, msg
    end

    validate_yaml!(yaml)

    @config[:endpoints] = configure_endpoints(yaml)
    @config[:certificates] = configure_certificates(yaml)
    @config[:connectors] = configure_connectors(yaml)
    
  end

  # Get hash of all configured endpoints.
  #
  # Entry key is the name of the endpoint as specified in YAML config
  # Entry value is object of type Acme::Distributed::Endpoint
  #
  def endpoints
    @config[:endpoints]
  end

  # Get value for renew_days - which was either given on command line (-r),
  # was specified in the defaults section of the YAML configuration or was
  # explicitely set using renew_days=(value).
  #
  def renew_days
    @config[:renew_days]
  end

  # Set value for renew_days.
  #
  def renew_days=(days)
    @config[:renew_days] = days
  end

  def endpoint
    @config[:endpoint]
  end

  def endpoint=(endpoint)
    @config[:endpoint] = endpoint
  end

  def certificates
    @config[:certificates]
  end

  def certificates=(certificates)
    @config[:certificates] = certificates
  end

  def connectors
    @config[:connectors]
  end
  
  def connectors=(connectors)
    @config[:connectors] = connectors
  end

  def options
    @options
  end
  
  # Get the default value for a given key
  #
  def default(key)
    @defaults[key.to_s]
  end

  # Return the class for a given connector type
  def connector_class(connector_type)
    if VALID_CHALLENGE_TYPES[connector_type]
      return VALID_CHALLENGE_TYPES[connector_type]
    else
      raise Acme::Distributed::ConfigurationError, "Invalid connector type: #{connector_type}, no connector class defined."
    end
  end

  private

  # Set the default value for a given key
  #
  def set_default(key, value)
    @defaults[key.to_s] = value
  end

  # Configure all endpoints from the YAML definition.
  #
  def configure_endpoints(yaml)
    endpoints = {}
    yaml['endpoints'].keys.each do |endpoint_name|
      @logger.debug("Processing configuration for endpoint #{endpoint_name}")
      endpoint = Acme::Distributed::Endpoint.new(endpoint_name, yaml['endpoints'][endpoint_name])
      endpoints[endpoint.name] = endpoint
      @logger.debug("Added endpoint configuration '#{endpoint.name}'")
    end
    endpoints
  end

  # Configure all certificates from the YAML definition
  #
  def configure_certificates(yaml)
    certificates = {}
    yaml['certificates'].keys.each do |certificate_name|
      @logger.debug("Processing configuration for certificate #{certificate_name}")
      certificate = Acme::Distributed::Certificate.new(certificate_name, yaml['certificates'][certificate_name], @options, @defaults)
      if not certificate.renew_days
        certificate.renew_days = renew_days
      end
      @logger.debug("Added certificate name='#{certificate.name}', subject='#{certificate.subject}' #{certificate.san.length} SAN entries, #{certificate.renew_days} renew days")
      certificates[certificate.name] = certificate
    end
    certificates
  end

  # Configure all connectors from the YAML definition. The configuration will
  # be stored in a two-level hash, with the top level being the challenge type
  # the connector implements and the second level the name of the connector.
  #
  def configure_connectors(yaml)
    connectors = {}

    VALID_CHALLENGE_TYPES.keys.each do |name|
      connectors[name] = {}
    end

    yaml['connectors'].each do |connector_name, config|
      @logger.debug("Processing configuration for connector '#{connector_name}'")
      if not config['type']
        raise Acme::Distributed::ConfigurationError, "Connector #{connector_name} has no type attribute"
      end
      connector_class = self.connector_class(config['type'])
      @logger.debug("Instantiating new connector from class #{connector_class.to_s}")
      connector = connector_class.new(connector_name, config, @options, @defaults)
      connectors[config['type']][connector.name] = connector
      @logger.debug("Added connector name='#{connector.name}', hostname='#{connector.hostname}'")
    end
    return connectors
  end

  # Validate the configuration that was loaded from the YAML. 
  #
  # Raises Acme::Distributed::ConfigurationError upon any error found in the
  # configuration.
  #
  def validate_yaml!(yaml)
    REQUIRED_CONFIG_KEYS.each do |key|
      if not yaml[key] or not yaml[key].is_a?(Hash)
        raise Acme::Distributed::ConfigurationError, "(file=#{@filename}) #{key} section missing or invalid (must be map)"
      end
    end

    # Perform sanity check on the default section too, if it exist.
    #
    if yaml['defaults']
      if yaml['defaults'].is_a?(Hash)
        yaml['defaults'].keys.each do |item|
          if not VALID_DEFAULT_KEYS.keys.include?(item.to_s)
            raise Acme::Distributed::ConfigurationError, "(file=#{file}) invalid item in defaults section: #{item.to_s}"
          end
          if not yaml['defaults'][item].is_a?(VALID_DEFAULT_KEYS[item])
            raise Acme::Distributed::ConfigurationError, "(file=#{file}) #{item.to_s} in defaults section must be #{VALID_DEFAULT_KEYS[item].to_s}"
          end
          @logger.debug("Setting default for #{item} to #{yaml['defaults'][item]}")
          set_default(item, yaml['defaults'][item]) 
        end
      else
        raise Acme::Distributed::ConfigurationError, "(file=#{file}) defaults section must be map, but is #{yaml['defaults'].class.to_s}"
      end
    end
  end

  def validate_defaults!(config)

  end

end

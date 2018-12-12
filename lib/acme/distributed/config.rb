require 'yaml'

require 'acme/distributed/logger'

require 'acme/distributed/endpoint'
require 'acme/distributed/certificate'
require 'acme/distributed/challenge_server'

class Acme::Distributed::Config

  # List of required keys in configuration YAML
  #
  REQUIRED_CONFIG_KEYS = [ "endpoints", "certificates", "challenge_servers" ]

  # List of valid keys for defaults section 
  #
  VALID_DEFAULT_KEYS = {
    "endpoint" => String,
    "renew_days" => Integer
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
    @config[:servers] = configure_servers(yaml)
    
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

  def servers
    @config[:servers]
  end
  
  def servers=(servers)
    @config[:servers] = servers
  end

  def options
    @options
  end
  
  # Get the default value for a given key
  #
  def default(key)
    @defaults[key.to_s]
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

  # Configure all servers from the YAML definition
  #
  def configure_servers(yaml)
    servers = {}
    yaml['challenge_servers'].keys.each do |server_name|
      @logger.debug("Processing configuration for challenge server '#{server_name}'")
      server = Acme::Distributed::ChallengeServer.new(server_name, yaml['challenge_servers'][server_name], @options, @defaults)
      servers[server.name] = server
      @logger.debug("Added challenge server name='#{server.name}', hostname='#{server.hostname}'")
    end
    servers
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

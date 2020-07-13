require 'acme/distributed/logger'
require 'acme/distributed/config'
require 'acme/distributed/challenge'

require 'acme/distributed/connector'

require 'acme/distributed/errors'
require 'acme/distributed/account'

class Acme::Distributed::Client

  # Initializes a new client object
  #
  # @param config_path [String] Path to the YAML configuration for this client
  # @param options [Acme::Distributed::Options] Options for this client
  # @raise [TypeError] Invalid parameters passed
  # @raise [Acme::Distributed::ConfigurationError] Invalid configuration passed
  #
  def initialize(config_path, options)
    if not options.kind_of?(Acme::Distributed::Options)
      raise TypeError, "options must be subclass of Acme::Distributed::Options"
    end   

    @logger = Acme::Distributed::Logger.new(options.log_level)
    @config = Acme::Distributed::Config.new(config_path, options)
    @options = options

    @endpoint = set_endpoint(options)
    
    # Create private key for account if key does not exist and key generation
    # option was set. If key does not exist and generation option was not set,
    # raise an error.
    #
    # Also, if we create an account key, we have to create the ACME account
    # as well. 
    #
    if not @endpoint.key_exist?
      if @options.generate_account_keys? and @options.create_account?
        @logger.info("Generating private account key for endpoint='#{@endpoint.name}' at path='#{@endpoint.private_key}'")
        Acme::Distributed::Util.generate_private_key!(@endpoint.private_key)
        #create_acme_account!(@endpoint)
      else
        raise Acme::Distributed::ConfigurationError, "Private key for endpoint='#{@endpoint.name}' at path='#{@endpoint.private_key}' does not exist."
      end
    end

  end

  # Run the client with the requested action
  #
  # @return nothing
  # @throw [Acme::Distributed::ConfigurationError] Invalid action configured
  # @throw Various exceptions can be thrown from the underlying methods
  #
  def run
    case @options.action
    when Acme::Distributed::Options::ACTION_REQUEST_CERT
      @logger.info("Starting certificate(s) request")
      request_certificates!
    when Acme::Distributed::Options::ACTION_CREATE_ACCOUNT
      @logger.info("Creating new ACME account")
      create_acme_account!(@endpoint)
    when Acme::Distributed::Options::ACTION_DISABLE_ACCOUNT
      @logger.info("Disabling ACME account")
    when Acme::Distributed::Options::ACTION_CHANGE_ACCOUNT
      @logger.info("Changing ACME account")
    else
      raise Acme::Distributed::ConfigurationError, "Unknown action: #{@options.action.to_s}"
    end
  end

  # The main loop for requesting certificates.
  #
  def request_certificates!
   
    @logger.info("Using endpoint name='#{@endpoint.name}', uri='#{@endpoint.uri}', key='#{@endpoint.private_key}'")
    @logger.info("Configured #{@config.connectors.keys.length} connectors.")

    if not @options.renew_days
      if not @config.default(:renew_days)
        @config.renew_days = 30
      else
        @config.renew_days = @config.default(:renew_days)
      end
    else
      @config.renew_days = @options.renew_days
    end

    @logger.info("Using a default renew_days value of #{@config.renew_days}")

    # First, gather which certificates to process in this run.
    #
    certificates = []
    @config.certificates.each do |cert_name, certificate|
      if @config.options.certificates.length == 0 || @config.options.certificates.include?(cert_name)
        
        # Replace all variables for the certificate currently processed.
        #
        certificate.replace_variables!(@endpoint)

        # If the certificate's private key does not exist, create it when the
        # appropriate option was set. If the option was not set, skip this
        # certificate.
        #
        if not certificate.key_exist?
          if @options.generate_certificate_keys?
            @logger.info("Generating private key for certificate='#{certificate.name}' at path='#{certificate.key}'")
            begin
              Acme::Distributed::Util.generate_private_key!(certificate.key)
            rescue Acme::Distributed::ConfigurationError => msg
              @logger.error("Could not generate private key at path='#{certificate.key}': #{msg}")
              next
            end
          else
            @logger.error("Private key for certificate='#{certificate.name}' does not exist at path='#{certificate.key}', skipping this certificate.")
            next
          end
        end

        if certificate.renewable?
          @logger.info("Considering cert='#{certificate.name}', remaining='#{certificate.remaining_lifetime}', renew_days='#{certificate.renew_days}' for renewal")
          certificates << certificate
        else
          @logger.info("Won't process cert='#{certificate.name}', remaining='#{certificate.remaining_lifetime}', renew_days='#{certificate.renew_days}'")
        end
      else
        @logger.debug("Skipping #{certificate.name} from processing due to name restrictions.")
      end
    end

    @logger.info("Considered #{certificates.length} (from a total of #{@config.certificates.length}) certificates for renewal/request.")

    # Connect to all required connectors for this challenge, when we considered
    # at least 1 certificate for renewal and regardless of run mode.
    #
    if certificates.length > 0
      certificates.each do |certificate|
        @logger.debug("Going to connect all connectors of type '#{certificate.connector_group}'")
        @config.connectors[certificate.connector_group].each do |connector_name, connector|
          connector.connect!
        end
      end
    end

    # This is our final list of certificates to process. We initiate a challenge
    # for every cert in the list.
    #
    # This may raise Acme::Distributed::ChallengeError
    #
    certificates.each do |certificate|
      @logger.info("Processing certificate name='#{certificate.name}', remaining lifetime='#{certificate.remaining_lifetime}' days.")

      # Some checks beforehand. Can we write the PEM? Can we read the key?
      #
      if not certificate.pem_writable?
        @logger.error("PEM file for certificate='#{certificate.name}' at path='#{certificate.path}' not writable, skip this certificate.")
        next
      elsif not certificate.key_exist?
        @logger.error("Private key file for certificate='#{certificate.name}' at path='#{certificate.key}' not readable, skip this certificate.")
        next
      end

      if @options.dry_run?
        @logger.info("Option --dry-run was specified, won't perform ACME requests.")
      else
        challenge = Acme::Distributed::Challenge.new(@endpoint, certificate, @config, @ooptions)
        challenge.start!

        # Should not happen -- but if there are no authorization requests, we
        # skip the current certificate.
        #
        if challenge.authorizations.length < 1
          @logger.warn("No authorization requests received for certificate name=#{certificate.name}")
          next
        end

        @logger.debug("#{challenge.authorizations.length} authorizations need to be fullfilled for this certificate.")

        cleanup_connectors = []

        # Create challenge responses for each authorization request on all
        # connectors.
        #
        challenge.authorizations.each do |authorization|
          @config.connectors[certificate.connector_group].each do |connector_name, connector|
            authorization_type = connector.authorization_type
            case connector.authorization_type
            when "http-01"
              challenge_name = authorization.http.filename
              challenge_content = authorization.http.file_content
            when "dns-01"
              challenge_name = authorization.dns.record_name
              challenge_content = authorization.dns.record_content
            else
              @logger.error("Unknown authorization type: #{connector.authorization.type}")
              next
            end

            begin
              connector.create_challenge(authorization.domain, challenge_name, challenge_content)
              cleanup_connectors << connector
            rescue Acme::Distributed::ServerError => msg
              @logger.error(msg)
            end
          end
        end

        # At this point, we can request the ACME endpoint to perform the actual
        # authorization of our requests.
        #
        begin
          challenge.validate!
        rescue StandardError => msg
          @logger.error("Could not authorize certificate #{certificate.name}: #{msg}")
        end

        # Remove all challenge files that we have created.
        #
        if cleanup_connectors.length > 0
          errors = 0
          cleanup_connectors.each do |connector|
            errors = connector.remove_all_challenges
          end
          if errors > 0
            @logger.warn("While removing challenges, #{errors} errors where encountered. Please check manually.")
          end
        else
          @logger.warn("No challenges were created.")
        end

        # All of our authorization were valid in this challenge. We can now go
        # ahead and finalize the order by requesting the certificate from the
        # endpoint.
        #
        if challenge.valid?
          @logger.info("Successfully completed all authorizations, requesting final certificate for #{certificate.name}")
          cert_data = challenge.finalize!
          @logger.info("Writing PEM data to #{certificate.path}")
          File.open(certificate.path, "w") do |f|
            f.write(cert_data)
          end
        else
          @logger.error("Could not complete all authorizations for certificate #{certificate.name}")
        end
      end 
    end

    # Terminate all connectors which have an established connection.
    #
    certificates.each do |certificate|
      @config.connectors[certificate.connector_group].each do |connector_name, connector|
        if connector.connected?
          connector.disconnect!
        end
      end
    end

  end

  def create_acme_account!(endpoint)
    Acme::Distributed::Account.create(endpoint, nil)
  end

  private

  # Check which endpoint to use from the ones found in the YAML configuration.
  #
  # If an endpoint name was given on the command line, we use that. Otherwise,
  # we check if there is one configured as default.
  #
  # Specifying the endpoint to use is mandatory; raise an error if neither of
  # the above settings exist. Same for specifying a non-existing endpoint.
  #
  def set_endpoint(options)
    if not options.endpoint
      if not @config.default(:endpoint)
        raise Acme::Distributed::ConfigurationError, "Endpoint is not specified and no default is set in configuration."
      end
      _endpoint = @config.default(:endpoint)
    else
      _endpoint = options.endpoint
    end

    if not @config.endpoints.keys.include?(_endpoint)
      raise Acme::Distributed::ConfigurationError, "Endpoint '#{_endpoint}' requested, but no such endpoint configured."
    end
    @config.endpoints[_endpoint]
  end

end
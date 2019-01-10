require 'openssl'
require 'acme/client'

require 'acme/distributed/logger'
require 'acme/distributed/endpoint'
require 'acme/distributed/certificate'

require 'acme/distributed/challenge_error'

# XXX: This needs a little overhaul.
#
class Acme::Distributed::Challenge

  CHALLENGE_STATE_ERROR = -1
  CHALLENGE_STATE_NEW = 0
  CHALLENGE_STATE_STARTED = 1

  # Creates a new challenge.
  #
  # @param endpoint [Acme::Distributed::Endpoint] The ACME endpoint to use for requests
  # @param certificate [Acme::Distributed::Certificate] the certificate to request
  # @param options [Hash] Hash of options
  #
  def initialize(endpoint, certificate, config, options)
    @logger = Acme::Distributed::Logger.new

    @endpoint = endpoint
    @certificate = certificate
    @config = config
    @options = options

    @acme_client = nil
    @authorizations = []
  
    # Current state of our challenge
    @challenge_state = CHALLENGE_STATE_NEW
  end

  def status
    @challenge_state
  end

  def status=(status)
    @challenge_state = status
  end

  def authorizations
    @authorizations
  end

  # Start the ACME challenge and order a new certificate.
  #
  def start!
    if self.status != CHALLENGE_STATE_NEW
      raise Acme::Distributed::ChallengeError, "Challenge already in progress, restart not possible."
    end

    @logger.info("Starting new ACME challenge for certificate='#{@certificate.name}', subjects='#{@certificate.subjects.join(",")}'")
    begin
      acme_account_key = OpenSSL::PKey::RSA.new(File.read(@endpoint.private_key))
    rescue StandardError => msg
      self.status = CHALLENGE_STATE_ERROR
      raise Acme::Distributed::ChallengeError, msg
    end

    @acme_client = Acme::Client.new(private_key: acme_account_key, directory: @endpoint.uri)

    @logger.debug("Created new Acme::Client object for endpoint='#{@endpoint.uri}' with private_key='#{@endpoint.private_key}'")

    # Now that we have the Acme::Client object, we can request a new order at
    # the configured endpoint.
    #
    begin
      @order = @acme_client.new_order(identifiers: @certificate.subjects)
    rescue StandardError => msg
      self.status = CHALLENGE_STATE_ERROR
      @logger.debug("We have an error!")
      raise Acme::Distributed::ChallengeError, msg
    end

    # For each subject in the certificate, we should now have an authorization
    # request that we must fill. We will be quite 
    timeouts = 0
    success = false 
    while timeouts < @endpoint.timeout_retries + 1 and not success
      @authorizations = []
      begin
        @order.authorizations.each do |authorization|
          @authorizations << authorization
        end
        success = true
      rescue Acme::Client::Error::Timeout => msg 
        timeouts += 1
        @logger.debug("We hit a timeout error, we retry (#{timeouts}/#{@endpoint.timeout_retries}): #{msg}")
      end
    end
    if not success
      raise Acme::Distributed::ChallengeError, "Could not get authorizations due to Acme::Client::Error::Timeout"
    end

    self.status = CHALLENGE_STATE_STARTED
  end

  # Request validation for all authorizations in our certificate challenge.
  # Usually, one authorization per certificate subject (CN and SAN) must be
  # fullfilled.
  #
  def validate!
    if self.status != CHALLENGE_STATE_STARTED
    end
    @logger.debug("Requesting authorization for certificate with subjects '#{@certificate.subjects.join(",")}'")
    @authorizations.each do |authorization|
      num_timeouts = 0
      authorizer = get_authorizer(authorization)
      authorizer.request_validation
      while authorizer.status == "pending"
        sleep(2)
        begin
          authorizer.reload
        rescue Acme::Client::Error::Timeout
          num_timeouts += 1
          @logger.debug("Received ACME timeout no##{num_timeouts} of max. #{@endpoint.timeout_retries}")
          if num_timeouts >= @endpoint.timeout_retries + 1
            raise Acme::Distributed::ServerError, "Abort authorization request, max. number of timeouts exceeded"
          end
        end
      end
      @logger.debug("Status of this authorization request: #{authorizer.status}")
    end
  end

  # Return true when all authorizations that we requested are in status valid.
  #
  def valid?
    @authorizations.each do |authorization|
      authorizer = get_authorizer(authorization)
      if authorizer.status != "valid"
        return false
      end
    end
    return true
  end

  # Finalize our order when all authorizations were valid. By finalizing,
  # ACME will issue our certificate which we in turn write to the local
  # file system.
  #
  def finalize!
    cert_key = OpenSSL::PKey::RSA.new(File.read(@certificate.key))
    csr = Acme::Client::CertificateRequest.new(private_key: cert_key, subject: { common_name: @certificate.subject }, names: @certificate.subjects )

    @order.finalize(csr: csr)
    while @order.status == "pending"
      sleep(1)
    end
    @logger.debug("Order status: #{@order.status}")
    timeouts = 0
    certificate = nil
    while timeouts < @endpoint.timeout_retries + 1 and not certificate
      begin
        certificate = @order.certificate
      rescue Acme::Client::Error::Timeout
        timeouts += 1
        @logger.debug("We hit a timeout (#{timeouts}/10)")
      end
    end
    if not certificate
      raise Acme::Distributed::ChallengeError, "Could not finalize the order due to Acme::Client::Error::Timeout"
    end
    return certificate
  end

  private

  # XXX: This is just a workaround for now, the authorization type for each
  # XXX: challenge belongs elsewhere.
  #
  def get_authorizer(authorization)
    authorization_type = @config.connectors[@certificate.connector_group].first[1].authorization_type
    @logger.debug("Getting authorizer for type #{authorization_type}")
    case authorization_type
    when "http-01"
      authorizer = authorization.http
    when "dns-01"
      authorizer = authorization.dns
    else
      raise Acme::Distributed::ServerError, "Unknown authorization type: #{authorization_type}"
    end
    authorizer
  end
end

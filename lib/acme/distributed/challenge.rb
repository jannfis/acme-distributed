require 'openssl'
require 'acme/client'

require 'acme/distributed/logger'
require 'acme/distributed/endpoint'
require 'acme/distributed/certificate'

require 'acme/distributed/challenge_error'

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
  def initialize(endpoint, certificate, options)
    @logger = Acme::Distributed::Logger.new

    @endpoint = endpoint
    @certificate = certificate
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
      raise Acme::Distributed::ChallengeError, msg
    end

    # For each subject in the certificate, we should now have an authorization
    # request that we must fill.
    @order.authorizations.each do |authorization|
      @authorizations << authorization
    end

    self.status = CHALLENGE_STATE_STARTED
  end

  def validate!
    if self.status != CHALLENGE_STATE_STARTED
    end
    @logger.debug("Requesting authorization for certificate with subjects #{@certificate.san.join(",")}")
    @authorizations.each do |authorization|
      num_timeouts = 0
      authorization.http.request_validation
      while authorization.http.status == "pending"
        sleep(2)
        begin
          authorization.http.reload
        rescue Acme::Client::Error::Timeout
          num_timeouts += 1
          @łogger.debug("Received ACME timeout no##{num_timeouts} of max. 5")
          if num_timeouts > 5
            raise Acme::Distributed::ServerError, "Abort authorization request, max. number of timeouts exceeded"
          end
        end
      end
      @logger.debug("Status of this authorization request: #{authorization.http.status}")
    end
  end

  def valid?
    @authorizations.each do |authorization|
      if authorization.http.status != "valid"
        return false
      end
    end
    return true
  end

  def finalize!
    cert_key = OpenSSL::PKey::RSA.new(File.read(@certificate.key))
    csr = Acme::Client::CertificateRequest.new(private_key: cert_key, subject: { common_name: @certificate.subject }, names: @certificate.subjects )
    @order.finalize(csr: csr)
    while @order.status == "pending"
      sleep(1)
    end
    @logger.debug("Order status: #{@order.status}")
    return @order.certificate
  end
end

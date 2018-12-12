require 'openssl'

require 'acme/distributed/logger'
require 'acme/distributed/configuration_error'

class Acme::Distributed::Certificate
  REQUIRED_CONFIG_KEYS = [ "subject", "path", "key" ]

  # Instantiate a new Certificate object
  #
  # @param name [String] The (symbolic) name of this certificate - NOT the subject of the cert.
  # @param config [Hash] Configuration hash describing the certificate
  # @param options [Acme::Distributed::Options] (optional): Set of user supplied options
  # @param defaults [Hash] Set of default options
  #
  def initialize(name, config, options, defaults = {})
    @logger = Acme::Distributed::Logger.new

    @name = name
    @config = config
    @options = options
    @defaults = defaults || {}

    # Cache value for certificate's remaining lifetime.
    @remaining_lifetime = nil

    validate!
  end

  # Returns the (symbolic) name of this certificate
  #
  # This is NOT the certificate's subject.
  #
  def name
    @name
  end

  # Alias for #subjects
  #
  def names
    subjects
  end

  # Returns an array of all subjects for this certificate (including all SAN
  # entries)
  #
  # @param sort [boolean] Whether result should be alphabetically sorted
  #
  def subjects(sort = true)
    _subjects = self.san.dup
    _subjects << self.subject
    if sort
      return _subjects.sort
    else
      return _subjects
    end
  end

  # Returns the path on the filesystem where this certificate is stored.
  #
  def path
    @config["path"]
  end

  def path=(value)
    @config["path"] = value
  end

  # Returns the path on the filesystem where the private key for this certifcate
  # is stored.
  #
  def key
    @config["key"]
  end

  def key=(value)
    @config["key"] = value
  end

  # Returns the common name (subject) for this certificate
  #
  def subject
    @config["subject"]
  end

  def subject=(value)
    @config["subject"] = value
  end

  # Returns the list of SAN entries for this certificate
  #
  def san
    @config["san"]
  end

  def san=(value)
    @config["san"] = value
  end

  # Returns the configured number of days needed to be left in the lifetime of
  # this certificate before it is considered for renewal.
  #
  def renew_days
    @config["renew_days"]
  end

  def renew_days=(value)
    @config["renew_days"] = value
  end

  # Returns true if the certificate's PEM exists on the local system, otherwise
  # returns false.
  #
  def pem_exist?
    File.exist?(self.path) && File.readable?(self.path)
  end

  # Checks if we can write to the PEM file. If that file exists, the file must
  # be writeable. If it does not yet exist, the path must be writeable.
  #
  def pem_writable?
    if (File.exist?(self.path) and File.writable?(self.path)) or (not File.exist?(self.path) and File.writable?(File.dirname(self.path)))
      return true
    else
      return false
    end
  end

  # Returns true if the certificate's key exists on the local system, otherwise
  # returns false.
  #
  def key_exist?
    File.exist?(self.key) and File.readable?(self.key)
  end

  # Returns whether this certificate is a candidate for renewal. This is true
  # if:
  #
  # - Cert does not exist on disk
  # - Cert exists on disk and remaining lifetime is <= renew_days
  #
  def renewable?
    if self.pem_exist?
      if remaining_lifetime <= renew_days
        return true
      else
        return false
      end
    else
      true
    end
  end

  # Returns the remaining lifetime of this certificate in days.
  #
  def remaining_lifetime(cached = true)
    # Return from cache if available and not disabled
    return @remaining_lifetime if @remaining_lifetime and cached
    if self.pem_exist?
      cert = OpenSSL::X509::Certificate.new(File.read(self.path))
      @remaining_lifetime = (cert.not_after - Time.now).to_i / 86400
      return @remaining_lifetime
    else
      return 0
    end
  end

  private

  def validate!
    if not @config.is_a?(Hash)
      raise Acme::Distributed::ConfigurationError, "Configuration for certificate #{@name} is not a Hash"
    end
    REQUIRED_CONFIG_KEYS.each do |key|
      if not @config.keys.include?(key)
        raise Acme::Distributed::ConfigurationError, "Incomplete configuration for certificate '#{@name}': Property '#{key}' is missing"
      end
    end

    # Check for existence and validity of optional 'san' property
    #
    if not @config["san"].nil?
      if @config["san"].is_a?(Array)
        @config["san"].each do |san|
          if not san.is_a?(String)
            raise Acme::Distributed::ConfigurationError, "List of SAN entries for certificate #{@name} contains non-string values"
          end
        end
      else
        raise Acme::Distributed::ConfigurationError, "Property 'san' for certificate '#{@name}' must be array of strings"
      end
    else
      @config["san"] = []
    end

    # Check for existence and validity of optional 'renew_days' property.
    #
    # renew_days given via command line overrides all other values.
    if @options.renew_days
      @config["renew_days"] = @options.renew_days
    elsif not @config["renew_days"].nil?
      if @config["renew_days"].is_a?(Integer)
        if @config["renew_days"] < 1
          raise Acme::Distributed::ConfigurationError, "Property 'renew_days' for certificate '#{@name}' must be > 0"
        end
      else
        raise Acme::Distributed::ConfigurationError, "Property 'renew_days' for certificate '#{@name}' must be Integer"
      end
    else
      @config["renew_days"] = @defaults["renew_days"] || 0
    end
  end
end

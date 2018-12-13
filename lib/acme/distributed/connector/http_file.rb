require 'net/ssh'
require 'securerandom'

require 'acme/distributed/logger'

require 'acme/distributed/configuration_error'
require 'acme/distributed/server_error'
require 'acme/distributed/connector/ssh'

class Acme::Distributed::Connector::HTTPFile < Acme::Distributed::Connector::SSH

  # These keys must exist in the config hash
  REQUIRED_CONFIG_KEYS = [ "hostname", "username", "acme_path" ]

  # Creates a new ChallengeServer instance
  #
  # @param name [String]
  # @param config [Hash]
  # @param options [Acme::Distributed::Options]
  # @param defaults [Hash]
  #
  def initialize(name, config, options, defaults)
    super(name, config, options, defaults)
    @challenges = []
    validate!
  end

  def create_challenge(filename, contents)
    check_connection!

    if filename !~ /^\.well-known\/acme\-challenge\/[a-zA-Z0-9\_\-]+$/
      raise Acme::Distributed::ServerError, "Received malformed filename for authorization fullfilment (filename='#{filename}')"
    end

    if contents !~ /^[a-zA-Z0-9\_\-\=\.]+$/
      raise Acme::Distributed::ServerError, "Received malformed contents for authorization (content=#{contents})"
    end
    
    # Remember path to this challenge for later.
    #
    challenge_path = self.acme_path + "/" + File.basename(filename)

    @logger.debug("Creating challenge content at #{challenge_path} on server=#{self.name}")
    retval = @ssh.exec!("echo '#{contents}' > '#{challenge_path}' && echo -n success").chomp
    if retval != "success"
      raise Acme::Distributed::ServerError, "Error creating challenge on server name=#{self.name}: #{retval}"
    end
    @challenges << challenge_path
  end

  def remove_challenge(challenge)
    check_connection!
    @logger.debug("Removing challenge file at #{challenge} on server=#{self.name}")
    retval = @ssh.exec!("test -f '#{challenge}' && rm -f '#{challenge}' && echo -n success").chomp
    if retval != "success"
      return false
    end
    return true
  end

  def remove_all_challenges
    errors = 0
    @challenges.each do |challenge|
      if not remove_challenge(challenge)
        errors += 1
      end
    end
    return errors
  end

  def name
    @name
  end

  def username
    @config['username']
  end

  def username=(value)
    @config['username'] = value
  end

  def hostname
    @config['hostname']
  end

  def hostname=(value)
    @config['hostname'] = value
  end

  def acme_path
    @config['acme_path']
  end

  def acme_path=(value)
    @config['acme_path'] = value
  end

  private

  def check_connection!
    if not @ssh
      raise Acme::Distributed::ServerError, "Challenge server name=#{self.name} is not connected."
    end
  end

  def validate!
    if not @config.is_a?(Hash)
      raise Acme::Distributed::ConfigurationError, "Configuration for challenge server '#{@name}' is not a Hash"
    end

    REQUIRED_CONFIG_KEYS.each do |key|
      if not @config.keys.include?(key)
        raise Acme::Distributed::ConfigurationError, "Incomplete configuration for challenge server '#{@name}': Property '#{key}' is missing"
      end
    end

    # Check for existence and validity of optional 'ssh_port' property
    if not @config["ssh_port"].nil?
      if not @config["ssh_port"].is_a?(Integer)
        raise Acme::Distributed::ConfigurationError, "Property 'ssh_port' for challenge server '#{@name}' must be integer."
      else
        if @config["ssh_port"] < 1 || @config["ssh_port"] > 65536
          raise Acme::Distributed::ConfigurationError, "Property 'ssh_port' for challenge server '#{@name}' must be between 1 and 65536."
        end
      end
    else
      @config["ssh_port"] = 22
    end

    # Let the caller know that it's not advised to use 'root' target user for
    # challenge servers.
    #
    if @config["username"] == "root"
      @logger.warn("User 'root' should not be used for connecting to #{@name}/hostname='#{@config['hostname']}")
    end
  end
end

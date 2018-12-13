require 'net/ssh'
require 'securerandom'

require 'acme/distributed/logger'

require 'acme/distributed/configuration_error'
require 'acme/distributed/server_error'

class Acme::Distributed::ChallengeServer

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
    @logger = Acme::Distributed::Logger.new
    @name = name
    @config = config
    @options = options
    @defaults = defaults || {}
    @ssh = nil
    @challenges = []
    validate!
  end

  def connect!(force_reconnect = false)
    if @ssh
      @logger.debug("SSH connection to server name='#{@name}', host=#{self.hostname} already established")
      if not force_reconnect
        return
      else
        @logger.debug("Forcing SSH reconnect for server name='#{@name}', host=#{self.hostname}")
      end
    end

    @logger.info("Establishing SSH connection to server name='#{@name}', host='#{self.hostname}', user '#{self.username}'")
    begin
      @ssh = Net::SSH.start(self.hostname, self.username, timeout: 2, non_interactive: true)
    rescue Net::SSH::AuthenticationFailed => msg
      raise Acme::Distributed::ServerError, "Could not establish SSH connection to server name='#{@name}': #{msg}"
    rescue StandardError => msg
      raise Acme::Distributed::ServerError, "Could not establish SSH connection to server name='#{@name}': #{msg}"
    end

    # With each connection, also test whether we are able to write (create and
    # delete a file) to the challenge path.
    #
    @logger.debug("Testing write access to #{self.acme_path}")
    test_file = self.acme_path + "/" + SecureRandom.uuid
    retval = @ssh.exec!("touch '#{test_file}' && rm -f '#{test_file}' && echo -n success").chomp
    if retval != "success"
      raise Acme::Distributed::ServerError, "No write access to #{self.acme_path} on challenge server #{self.name} (output=#{retval})"
    end
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

  def disconnect!
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

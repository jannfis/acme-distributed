require 'net/ssh'
require 'securerandom'

require 'acme/distributed/logger'

require 'acme/distributed/configuration_error'
require 'acme/distributed/server_error'
require 'acme/distributed/connector/ssh'

# This connector provides fullfillment of DNS authorizations with the unbound
# DNS server.
#
# It connects to the DNS server via SSH and runs unbound-control on the server
# to create the authorization RR.
#
class Acme::Distributed::Connector::SshDnsUnbound < Acme::Distributed::Connector::SSH

  # These keys must exist in the config hash
  REQUIRED_CONFIG_KEYS = [ "hostname", "username", "unbound_ctrl" ]

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

  # Connect to the remote DNS server and check whether we can execute unbound's
  # control program successfully.
  #
  def connect!(force_reconnect = false)
    super(force_reconnect)
   
    success = @ssh.exec!("test -x #{@config['unbound_ctrl']} && #{@config['unbound_ctrl']} list_local_zones >/dev/null && echo -n success")
    if success != "success"
      raise Acme::Distributed::ServerError, "Cannot execute #{@config['unbound_ctrl']} on host='#{self.name}'"
    end
  end

  # Create the TXT RR for authorization.
  #
  def create_challenge(subject, challenge_name, challenge_content)
    check_connection!

    if challenge_name !~ /^[a-zA-Z0-9\_\-]+$/
      raise Acme::Distributed::ServerError, "Received malformed filename for authorization fullfilment (RR='#{challenge_name}')"
    end

    if challenge_content !~ /^[a-zA-Z0-9\_\-\=\.]+$/
      raise Acme::Distributed::ServerError, "Received malformed contents for authorization (content=#{contents})"
    end

    record_name = "#{challenge_name}.#{subject}"
    
    @logger.debug("Creating challenge content for '#{subject}' at '#{record_name}' on server='#{self.name}'")

    # Create the RR using unbound-control
    #
    command = "#{@config['unbound_ctrl']} local_data #{record_name}. 5 IN TXT #{challenge_content} >/dev/null && echo -n success"
    @logger.debug("Executing: '#{command}'")
    retval = @ssh.exec!("#{@config['unbound_ctrl']} local_data #{record_name}. 5 IN TXT #{challenge_content} >/dev/null && echo -n success").chomp
    if retval != "success"
      raise Acme::Distributed::ServerError, "Error creating challenge for '#{subject}' on server name='#{self.name}': #{retval}"
    end

    # Remember the RR for later removal
    @challenges << record_name
  end

  # Remove the RR for the authorization request.
  #
  # Attention: This will remove ALL RRs for the given FQDN.
  #
  def remove_challenge(challenge)
    check_connection!
    @logger.debug("Removing challenge #{challenge} on server=#{self.name}")
    retval = @ssh.exec!("#{@config['unbound_ctrl']} local_data_remove #{challenge} >/dev/null && echo -n success").chomp
    if retval != "success"
      return false
    end
    return true
  end

  # Remove all challenges that haven been handled by this connector.
  #
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

  def authorization_type
    return "dns-01"
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

require 'net/ssh'

require 'acme/distributed/errors'
require 'acme/distributed/connector/base'

# Implementaiton of SSH connector for deriving SSH based connectors. This class
# should not be directly instantiated but sub-classed instead.
#
# It implements the connection logic and provides a @ssh instance variable for
# accessing the Net::SSH connection.
#
class Acme::Distributed::Connector::SSH < Acme::Distributed::Connector::Base

  def initialize(name, config, options, defaults)
    super(name, config, options, defaults)
  end

  # Establish SSH connection to the target server. If the connection is already
  # established, and force_reconnect is not set to true, reuse the connection.
  #
  # @param force_reconnect [Boolean] Whether to force reconnect if connection already established
  #
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
      @ssh = Net::SSH.start(self.hostname, self.username, port: @config['ssh_port'] || 22, timeout: 2, non_interactive: true)
    rescue Net::SSH::AuthenticationFailed => msg
      raise Acme::Distributed::ServerError, "Could not establish SSH connection to server name='#{@name}': #{msg}"
    rescue StandardError => msg
      raise Acme::Distributed::ServerError, "Could not establish SSH connection to server name='#{@name}': #{msg}"
    end
  end

  # Shutdown an already established connection to the target server.
  #
  def disconnect!
    @logger.info("Terminating SSH connection to server name=#{@name}")
    @ssh.close
    @ssh = nil
  end

  # Returns whether connection is established or not.
  #
  # @return [Boolean] true if connection is established, false if not.
  #
  def connected?
    if @ssh
      return true
    else
      return false
    end
  end

  # This method must be overwritten in the derived class
  def can_access?
    raise Acme::Distributed::ConnectorError, "#can_access? not implemented in derived class"
  end
end

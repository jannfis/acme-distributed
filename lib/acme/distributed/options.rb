require 'logger'

# Acme::Distributed::Options
#
# All classes implementing option settings or preferences must derive from 
# this class.
#
class Acme::Distributed::Options
  def initialize
    @options = default_options
  end
  
  def log_level
    @options[:log_level]
  end

  def log_level=(level)
    @options[:log_level] = level
  end

  def endpoint
    @options[:endpoint]
  end

  def endpoint=(value)
    @options[:endpoint] = value
  end

  def certificates
    @options[:certificates]
  end

  def certificates=(certificates)
    @options[:certificates] = certificates
  end

  def servers
    @options[:servers]
  end

  def servers=(servers)
    @options[:servers] = servers
  end

  def dry_run?
    @options[:dry_run]
  end

  def dry_run=(value)
    @options[:dry_run] = value
  end

  def renew_days
    @options[:renew_days]
  end

  def renew_days=(days)
    @options[:renew_days] = days
  end

  def options
    @options
  end

  private
  
  # Return a hash containing the defaults for command line parser.
  #
  # Returns:
  #   hash of default options
  #
  def default_options
    options = {
      :endpoint => nil,
      :certificates => [],
      :servers => [],
      :log_level => Logger::INFO,
      :renew_days => nil,
      :dry_run => false,
      :check_config => false,
    }
    options
  end
end

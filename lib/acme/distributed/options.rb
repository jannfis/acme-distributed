require 'logger'

# Acme::Distributed::Options
#
# All classes implementing option settings or preferences must derive from 
# this class.
#
class Acme::Distributed::Options

  ACTION_REQUEST_CERT = 1
  ACTION_CREATE_ACCOUNT = 2
  ACTION_DISABLE_ACCOUNT = 3
  ACTION_CHANGE_ACCOUNT = 4

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

  def generate_certificate_keys?
    @options[:generate_certificate_keys]
  end

  def generate_account_keys?
    @options[:generate_account_keys]
  end

  def create_account?
    @options[:create_account]
  end

  def deactivate_account?
    @options[:deactivate_account]
  end

  def change_account?
    @options[:change_account]
  end
  
  def options
    @options
  end

  def action
    if create_account?
      return ACTION_CREATE_ACCOUNT
    elsif deactivate_account?
      return ACTION_DISABLE_ACCOUNT
    elsif change_account?
      return ACTION_CHANGE_ACCOUNT
    else
      return ACTION_REQUEST_CERT
    end
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
      :generate_certificate_keys => false,
      :generate_account_keys => false,
      :create_account => false,
      :deactivate_account => false,
      :change_account => false
    }
    options
  end
end

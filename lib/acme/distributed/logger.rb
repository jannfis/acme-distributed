require 'logger'

# Acme::Distributed::Logger
#
# Abstraction class for logging functions. Currently, uses Logger exclusively
# for implementing logging.
#
class Acme::Distributed::Logger

  @@logger = nil

  def initialize(log_level = nil)
    if not @@logger
      @@logger = Logger.new(STDOUT)
      level = log_level
    end
    if not log_level.nil?
      @@logger.level = log_level
    end
  end

  def info(msg)
    @@logger.info(msg)
  end

  def warn(msg)
    @@logger.warn(msg)
  end

  def debug(msg)
    @@logger.debug(msg)
  end

  def error(msg)
    @@logger.error(msg)
  end

  def fatal(msg)
    @@logger.fatal(msg)
  end

  def level
    @@logger.level
  end

  def logger
    @@logger
  end

  def level=(level)
    puts "Set log level: #{level}"
    @@logger.level = level
  end
end

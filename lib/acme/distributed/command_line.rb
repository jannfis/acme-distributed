require 'optparse'
require 'acme/distributed/options'

# Acme::Distributed::CommandLine
#
# This class handles calling acme-distributed via command line. 
#
# It expects stdout and stderr to be available, and uses it for printing 
# informational and error messages back to the caller.
#
class Acme::Distributed::CommandLine < Acme::Distributed::Options

  # Constructor.
  #
  # Parameters:
  #
  #   arguments 
  #     Array of command line arguments passed by user. Will be destructively
  #     modified. All valid options will be removed from the array.
  #
  #   program
  #     Name to display in usage message (optional)
  #
  def initialize(arguments, program = 'acme-distributed')
    @arguments = arguments
    @program = program

    super()

    begin
      parse_options
    rescue StandardError => msg
      raise Acme::Distributed::CommandLineError, msg
    end
  end

  # Get usage information from OptionParser instance. If not initialized, will
  # return a default string.
  #
  def self.usage
    if @@optionparser
      @@optionparser.help
    else
      "Unknown error occured :-("
    end
  end

  private

  # Parse all given command line options and fill @options hash accordingly. 
  #
  # Will initialize @@optionparser class variable.
  #
  # On error, will raise one of the following:
  #
  #   Acme::Distributed::CommandLineError 
  #   OptionParser::InvalidOption
  #   OptionParser::InvalidArgument
  #   OptionParser::
  #
  # Returns:
  #   nothing
  #
  def parse_options
    @@optionparser = OptionParser.new do |opts|
      opts.banner = "USAGE: #{@program} [options] <configuration.yaml>"
      
      # XXX: -V does exit. Unsure whether this is correct here.
      opts.on("-V", "--version", "Display version number and exit") do
        STDERR.puts(Acme::Distributed.versioninfo)
        STDERR.puts
        STDERR.puts(Acme::Distributed.copyright)
        exit 1
      end

      # -e|--endpoint
      # specifies ACME endpoint name to use
      opts.on("-e", "--endpoint <name>", String, "The ACME endpoint to use") do |endpoint|
        @options[:endpoint] = endpoint
      end

      # -c|--certificates <certlist>
      # list of certificates to process, comma separated
      opts.on("-c", "--certificates <cert1,[<cert2>[,...]]>", String, "List of certificiate names to process") do |certificates|
        certificates.split(",").each do |cert|
          @options[:certificates] << cert.strip
        end
      end

      # -s|--servers <serverlist>
      # list of servers to use for challenge validation, comma separated
      opts.on("-s", "--servers <server1[,<server2>[,...]]>", String, "List of servers to use for challenge verification") do |servers|
        servers.split(",").each do |server|
          @options[:servers] << server.strip
        end
      end

      # -r|--renew-days <days>
      # Number of days for the remaining lifetime of a cert to be processed
      opts.on("-r", "--renew-days <days>", Integer, "Only renew certificates which have a remaining validity less than <days> days") do |days|
        raise Acme::Distributed::CommandLineError, "renew days must be positive integer" if days < 0
        @options[:renew_days] = days
      end

      opts.on("-L", "--log-level <level>", String, "Log level to use [DEBUG, INFO, WARN, ERROR]. Default is INFO.") do |level|
        case level.downcase
        when "debug"
          @options[:log_level] = Logger::DEBUG
        when "info"
          @options[:log_level] = Logger::INFO
        when "warn"
          @options[:log_level] = Logger::WARN
        when "error"
          @options[:log_level] = Logger::ERROR
        else
          raise Acme::Distributed::CommandLineError, "unknown log level: #{level}"
        end
      end

      opts.on("-n", "--dry-run", "Just show what would be done, but do nothing.") do
        @options[:dry_run] = true
      end

    end
    @@optionparser.parse!(@arguments)
  end
end

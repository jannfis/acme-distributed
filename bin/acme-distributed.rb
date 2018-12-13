#!/usr/bin/env ruby

LIB_PATH = File.expand_path(File.dirname(__FILE__) + "/../lib")
$LOAD_PATH.unshift(LIB_PATH) unless $LOAD_PATH.include?(LIB_PATH)

require 'bundler/setup'
require 'acme-distributed'

# Parse command line options -- if any.
#
begin
  options = Acme::Distributed::CommandLine.new(ARGV, $0)
rescue Acme::Distributed::CommandLineError => msg
  STDERR.puts("ERROR: #{msg}")
  puts Acme::Distributed::CommandLine.usage
  exit 1
end

# We need exactly one argument to be left after parsing the options. This is
# the name of the configuration file to load.
#
if ARGV.length != 1
  STDERR.puts("ERROR: no configuration file was specified.")
  puts
  puts Acme::Distributed::CommandLine.usage
  exit 1
end

@logger = Acme::Distributed::Logger.new

# Run the client with our options -- exit on fatal errors.
#
begin
  client = Acme::Distributed::Client.new(ARGV[0], options)
rescue Acme::Distributed::ConfigurationError => msg
  @logger.fatal("Configuration error: #{msg.message}")
  exit 1
end

begin
  client.run
rescue StandardError => msg
  @logger.fatal(msg.message)
  exit 1
end

@logger.info("Success.")

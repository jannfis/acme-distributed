#!/usr/bin/env ruby

# This is free and unencumbered software released into the public domain.
# 
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
# 
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# For more information, please refer to <http://unlicense.org>
# 

# TODO: Better error handling
# TODO: Make Acme::Client::Error::Timeout resilient

require 'yaml'
require 'net/ssh'
require 'acme-client'
require 'optparse'
require 'logger'
require 'pp'

module Acme
  module Distributed
    DEBUG = true

    VERSION = "0.0.1"

    @logger = Logger.new(STDOUT)
    @logger.level = Logger::INFO

    def self.logger
      @logger
    end

    def self.versioninfo
      "Acme::Distributed version #{VERSION}"
    end

    class ConfigurationError < RuntimeError
    end

    # This class represents a webserver where the challenges will be served from.
    #
    # Valid options:
    #   hostname      - The host name to connect to
    #   username      - The username to connect with
    #   port          - Alternate SSH port (defaults to 22)
    #   acme_path     - The path on the FS to create challenge response at
    #
    class ChallengeServer
      def initialize(name, options)
        @name = name
        @options = options
      end

      def connect!
        Acme::Distributed.logger.debug("Connecting to #{@name} (Host: #{self.hostname} with user #{self.username}")
        @ssh = Net::SSH.start(self.hostname, self.username, timeout: 2)
      end

      def create_challenge(filename, contents)
        @challenge_path = self.acme_path + "/" + filename
        Acme::Distributed.logger.debug("Creating challenge content at #{@challenge_path}")
        @ssh.exec!("echo '#{contents}' > '#{@challenge_path}'")
      end

      def remove_challenge
        Acme::Distributed.logger.debug("Removing challenge file at #{@challenge_path}")
        @ssh.exec!("test -f '#{@challenge_path}' && rm -f '#{@challenge_path}'")
      end

      def disconnect!
      end

      def name
        @name
      end

      def username
        @options['username']
      end

      def username=(value)
        @options['username'] = value
      end

      def hostname
        @options['hostname']
      end

      def hostname=(value)
        @options['hostname'] = value
      end

      def acme_path
        @options['acme_path']
      end

      def acme_path=(value)
        @options['acme_path'] = value
      end
    end

    class Endpoint
      def initialize(name, options)
        @name = name
        @options = options
        validate
      end

      def name
        @name
      end

      def uri
        @options['url']
      end

      def uri=(value)
        @options['url'] = value
      end

      def url
        self.uri
      end

      def url=(value)
        self.uri = value
      end

      def private_key
        @options['private_key']
      end

      def private_key=(value)
        @options['private_key'] = value
      end

      def email_address
        @options['email_address']
      end

      def email_address=(value)
        @options['email_address'] = value
      end

      private

      def validate
        ["url", "private_key", "email_addr"].each do |key|
          if not @options[key]
            raise ArgumentError, "Incomplete endpoint configuration: #{key} is missing"
          end
        end
      end
    end

    class Certificate
      def initialize(name, options)
        @name = name
        @options = options
      end

      def name
        @name
      end

      def subject
        @options['subject']
      end

      def subject=(value)
        @options['subject'] = value
      end

      def key
        @options['key']
      end

      def key=(value)
        @options['key'] = value
      end

      def key?
        File.exists?(self.key)
      end

      def path
        @options['path']
      end

      def path=(value)
        @options['path'] = value
      end

      def san_entries
        @options['san']
      end

      def san_entries=(value)
        @options['san'] = value
      end

      def names
        _names = []
        _names << self.subject
        if self.san_entries and self.san_entries.kind_of?(Array)
          self.san_entries.each do |entry|
            _names << entry
          end
        end
        _names
      end

      def pem_data
        @pem_data
      end

      def pem_data=(value)
        @pem_data = value
      end
    end

    class Challenge

      def initialize(endpoint, certificate, options)
        @endpoint = endpoint
        @cert = certificate
        @options = options
      end

      def create(server)
        server.connect!
        @challenges.each do |challenge|
          Acme::Distributed.logger.debug("Creating challenge on server #{server.name}")
          Acme::Distributed.logger.debug("Filename sent was: #{challenge.filename}")
          if challenge.filename =~ /^\.well-known\/acme\-challenge\/[a-zA-Z0-9\_\-]+$/
            server.create_challenge(File.basename(challenge.filename), challenge.file_content)
          else
            Acme::Distributed.logger.error("Filename sent by ACME endpoint does not match a valid pattern -- this should not happen.")
          end
        end
      end

      # Initiate the ACME challenge.
      #
      def start!
        Acme::Distributed.logger.info("Initiating ACME challenge for certificate with names: " + @cert.names.to_s + " at endpoint #{@endpoint.uri}")
        keyobj = OpenSSL::PKey::RSA.new(File.read(@endpoint.private_key))
        @acme_client = Acme::Client.new(private_key: keyobj, directory: @endpoint.uri)
        @order = @acme_client.new_order(identifiers: @cert.names)
        authorizations = @order.authorizations
        @challenges = []
        authorizations.each do |authorization|
          Acme::Distributed.logger.debug("Authorization required.")
          @challenges << authorization.http
        end
      end

      # Tell ACME provider to validate the challenge after it is setup.
      #
      def validate!
        @challenges.each do |challenge|
          Acme::Distributed.logger.debug("Initiating challenge validation for DNS #{self.names}")
          challenge.request_validation
          num_timeouts = 0
          while challenge.status == 'pending'
            sleep(2)
            begin
              challenge.reload
            rescue Acme::Client::Error::Timeout
              Acme::Distributed.logger.debug("Timeout from ACME endpoint")
              num_timeouts += 1
              if num_timeouts > 5
                Acme::Distributed.logger.error("Aborting after 5th timeout from ACME endpoint")
                break
              end
            end
          end
          Acme::Distributed.logger.debug("Status of validation was: #{challenge.status}")
        end
      end

      def valid?
        @challenges.each do |challenge|
          if challenge.status != 'valid'
            return false
          end
        end
        return true
      end

      def finish!
        keyobj = OpenSSL::PKey::RSA.new(File.read(@cert.key))
        csr = Acme::Client::CertificateRequest.new(private_key: keyobj, subject: { common_name: @cert.subject }, names: @cert.names )
        @order.finalize(csr: csr)
        while @order.status == 'processing'
          sleep(1)
        end
        @cert.pem_data = @order.certificate 
      end

      def token
        @challenge.token
      end

      def content
        @challenge.file_content
      end

      def certificate
        @cert
      end

      def names
        @cert.names.to_s
      end

      def filename
        File.basename(@challenge.filename)
      end
    end

    class Config

      REQUIRED_CONFIG_KEYS = [ "endpoints", "certificates", "challenge_servers" ]

      # Load configuration from file
      #
      def initialize(file, options)
        Acme::Distributed.logger.info("Loading configuration from file #{file}")

        begin
          config = YAML.load(File.open(file).read)
        rescue StandardError => msg
          Acme::Distributed.fatal msg
        rescue RuntimeError => msg
          Acme::Distributed.fatal msg
        end

        REQUIRED_CONFIG_KEYS.each do |key|
          if not config[key]
            Acme::Distributed.fatal "Invalid configuration loaded: #{key} section missing."
          end
        end

        # Figure out which endpoint to use. It must be either specified via
        # command line or set as a default in the configuration.
        #
        # If no endpoint was set, error out.
        #
        if not options[:endpoint]
          if config["defaults"] and config["defaults"]["endpoint"]
            self.endpoint_name = config["defaults"]["endpoint"]
          else
            Acme::Distributed.logger.error("You need to either specify --endpoint or set a default in your configuration.")
            exit 1
          end
        else
          self.endpoint_name = options[:endpoint]
        end

        if not config["endpoints"][self.endpoint_name]
          Acme::Distributed.logger.error("Endpoint '#{self.endpoint_name}' is not configured.")
          Acme::Distributed.logger.error("Available endpoints: " + config["endpoints"].keys.join(", "))
          exit 1
        end

        @config = config

        configure_endpoints
        configure_certificates
        configure_challenge_servers
      end

      def endpoint_name
        @endpoint_name
      end

      def endpoint_name=(value)
        @endpoint_name = value
      end

      def endpoint
        @endpoint
      end

      def endpoint=(value)
        @endpoint = value
      end

      def endpoints
        @endpoints
      end

      def certificates
        @certificates
      end

      def challenge_servers
        @challenge_servers
      end

      private

      def configure_endpoints
        @endpoints = []
        if @config["endpoints"].nil?
          raise Acme::Distributed::ConfigError, "No endpoints definition in configuration"
        end
        if not @config["endpoints"].is_a?(Hash)
          raise Acme::Distributed::ConfigError, "endpoints must be a Hash of options"
        end

        @config["endpoints"].each do |key, endp|
          if endp["url"].nil? 
            raise Acme::Distributed::ConfigError, "Endpoint option 'url' for #{key} not valid or not defined."
          end
          if endp["private_key"].nil? 
            raise Acme::Distributed::ConfigError, "Endpoint 'private_key' for #{key} not valid or not defined."
          end
          if endp["email_addr"].nil? 
            raise Acme::Distributed::ConfigError, "Endpoint 'email_addr' for #{key} not valid or not defined."
          end
          endpoint = Endpoint.new(key, endp)
          @endpoints << endpoint
          if key == self.endpoint_name
            @endpoint = endpoint
          end
        end
      end

      def configure_certificates
        @certificates = []

        if @config["certificates"].nil?
          raise Acme::Distributed::ConfigError, "No certificates definition in configuration"
        end
        if not @config["certificates"].is_a?(Hash)
          raise Acme::Distributed::ConfigError, "certificates must be a Hash of options"
        end

        @config["certificates"].each do |key, cert|
          if cert["subject"].nil?
            raise Acme::Distributed::ConfigError, "Certificate option 'subject' for #{key} not valid or not defined."
          end
          if cert["path"].nil?
            raise Acme::Distributed::ConfigError, "Certificate option 'path' for #{key} not valid or not defined."
          end
          if cert["key"].nil?
            raise Acme::Distributed::ConfigError, "Certificate option 'key' for #{key} not valid or not defined."
          end
          if cert["san"] and not cert["san"].is_a?(Array)
            raise Acme::Distributed::ConfigError, "Certificate option 'san' for #{key} not valid (must be array)."
          end
          @certificates << Certificate.new(key, cert)
          Acme::Distributed.logger.debug("Configured certificate '#{key}': " + cert.to_s)
        end

      end # configure_certificates

      def configure_challenge_servers
        @challenge_servers = []

        if @config["challenge_servers"].nil?
          raise Acme::Distributed::ConfigError, "No challenge_servers definition in configuration"
        end
        if not @config["challenge_servers"].is_a?(Hash)
          raise Acme::Distributed::ConfigError, "challenge_servers must be a Hash of options"
        end

        @config["challenge_servers"].each do |key, server|
          if server["hostname"].nil?
            raise Acme::Distributed::ConfigError, "challenge_server option 'hostname' for #{key} not valid or not defined."
          end
          if server["acme_path"].nil?
            raise Acme::Distributed::ConfigError, "challenge_server option 'acme_path' for #{key} not valid or not defined."
          end
          @challenge_servers << ChallengeServer.new(key, server)
          Acme::Distributed.logger.debug("Configured challenge server '#{key}': " + server.to_s)
        end


      end # configure_challenge_servers

    end # Configuration

  end # Distributed

end # Acme


options = {}

OptionParser.new do |opts|
  opts.banner = "USAGE: #{$0} [options] <configuration>"

  opts.on("-V", "--version", "Display version number and exit") do
    STDERR.puts(Acme::Distributed.versioninfo)
    STDERR.puts
    STDERR.puts("This software is put into the Public Domain under the terms of Unlicense.")
    STDERR.puts("Refer to https://www.unlicense.org for more details.")
    exit 1
  end

  opts.on("-e", "--endpoint <name>", String, "The endpoint to use for the request") do |env|
    options[:endpoint] = env
  end

  options[:certificates] = []
  opts.on("-c", "--certificates <cert1[, cert2[, ...]]>", String, "Certificates to request") do |certs|
    certs.split(",").each do |cert|
      options[:certificates] << cert.strip
    end
  end

  options[:servers] = []
  opts.on("-s", "--servers <server1,[, server2[, ...]]>", String, "Servers to create challenge answers on") do |servers|
    servers.split(",").each do |server|
      options[:servers] << server.strip
    end
  end

  opts.on("-L", "--log-level <level>", String, "Log level to use [DEBUG, INFO, WARN, ERROR]. Default is INFO.") do |level|
    case level.downcase
    when "debug"
      Acme::Distributed.logger.level = Logger::DEBUG
    when "info"
      Acme::Distributed.logger.level = Logger::INFO
    when "warn"
      Acme::Distributed.logger.level = Logger::WARN
    when "error"
      Acme::Distributed.logger.level = Logger::ERROR
    end
  end

end.parse!

if ARGV.length != 1
  STDERR.puts "USAGE: #{$0} [options] <config.yml>"
  STDERR.puts "Call '#{$0} --help' to see a list of valid options."
  exit 1
end

config_file = ARGV[0]
config = Acme::Distributed::Config.new(config_file, options)

Acme::Distributed.logger.info("Using ACME endpoint #{config.endpoint.url}")

config.certificates.each do |cert|

  if cert.path =~ /\{\{[a-z]+\}\}/
    Acme::Distributed.logger.debug("Performing variable replacement in PEM path for certificate #{cert.name}")
    _path = cert.path.sub("{{endpoint}}", config.endpoint_name)
    cert.path = _path
    Acme::Distributed.logger.debug("Final path: #{cert.path}")
  end

  if cert.key =~ /\{\{[a-z]+\}\}/
    Acme::Distributed.logger.debug("Performing variable replacement in key path for certificate #{cert.name}")
    _key = cert.key.sub("{{endpoint}}", config.endpoint_name)
    cert.key = _key
    Acme::Distributed.logger.debug("Final path: #{cert.key}")
  end

  # The key for certificate request has to exist
  if not File.exists?(cert.key)
    Acme::Distributed.logger.warn("Key file #{cert.key} does not exist, skipping request for #{cert.name}")
    next
  end

  challenge = Acme::Distributed::Challenge.new(config.endpoint, cert, {})
  challenge.start!

  config.challenge_servers.each do |server|
    Acme::Distributed.logger.info("Connecting to challenge server #{server.name}")
    challenge.create(server)
  end

  challenge.validate!

  config.challenge_servers.each do |server|
    server.remove_challenge
  end

  if challenge.valid?
    Acme::Distributed.logger.info("Successfully completed all challenges. Certificate request now in progress...")
    challenge.finish!
    Acme::Distributed.logger.info("Writing PEM data to #{cert.path}")
    File.open(cert.path, "w") do |f|
      f.write(cert.pem_data)
    end
  else
    Acme::Distributed.logger.error("Challenges couldn't be completed, check your configuration and logs.")
  end

end



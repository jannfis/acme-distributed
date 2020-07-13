require 'openssl'
require 'acme/distributed/errors'
require 'acme/client'
require 'fileutils'

# This class implements basic ACME account management.
#
# TODO: This needs some error handling.
#
class Acme::Distributed::Account

  # Create ACME account at given endpoint
  def self.create(endpoint, options)
    if not File.exists?(endpoint.private_key)
      raise RuntimeError, "Oh oh"
    end
    client = Acme::Client.new(private_key: OpenSSL::PKey::RSA.new(File.read(endpoint.private_key)), directory: endpoint.uri)
    client.new_account(contact: endpoint.email_address, terms_of_service_agreed: true)
  end

  def self.deactivate(endpoint)
  end

  def self.change(endpoint)
  end

  private

  def self.create_account_key(path)
  end
end
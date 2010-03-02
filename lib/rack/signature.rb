# In Rails you could use:
# config.middleware.use "Rack::Signature"
require 'rack'
require 'oauth'
require 'oauth/consumer'
require 'oauth/request_proxy/rack_request'
require 'oauth/signature/rsa/sha1'
require 'oauth/signature/hmac/sha1'

# Verifies OAuth signature of gadget server, ensuring that requests are coming
# from opensocial platform, and are not forged
class Rack::Signature

  def initialize(app)
    @app = app
    @public_keys = {}

    # Locations of public keys for each platform
    @public_keys["http://shindig/public.cer"] = {:cert => File.open("config/certs/shindig.cert").read, :key => "XXXXXXXXXX", :secret => "YYYYYYYYYYYYYYYYY" }
  end

  def call(env)
    request = Rack::Request.new(env.clone)
    secrets = @public_keys[request[:xoauth_signature_publickey]]
    consumer = OAuth::Consumer.new(secrets[:key], secrets[:cert])

    begin
      pass = OAuth::Signature.build(request, :consumer => consumer).verify
    rescue OAuth::Signature::UnknownSignatureMethod => e
      puts "ERROR "+ e.message
    end

    raise "OAuth access denied"  unless pass

    status, headers, response = @app.call(env)
    [status, headers, response]
  end
end


# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'net/http'
require 'json'
require 'uri'
require 'net/https'

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Auth0Jwt < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "auth0jwt"
  
  # Replace the message with this value.
  config :domain, :validate => :string, :required => true
  config :purge_seconds, :validate => :number, :default => 3600
  config :include_user_properties, :validate => :array, :default => []

  public
  def register
    @cache = Hash.new
    @last_purge = Time.now
  end # def register

  public
  def filter(event)

    if @last_purge - Time.now > @purge_seconds
      @cache.clear
    end

    if !@cache[event['jwt']]
      data = {
        id_token: event['jwt']
      }
      uri = URI.parse("https://#{@domain}/tokeninfo")
      headers = {'Content-Type' => "application/json"}
      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = true
      request = Net::HTTP::Post.new(uri.request_uri, headers)
      request.body = data.to_json
      response = https.request(request)

      userHash = JSON.parse(response.body)

      include_user_properties.each { |user_property|

        if userHash[user_property]
          event.set(user_property, userHash[user_property])
        end
      }

      @cache[event['jwt']] = response.code == "200"
    end

    if @cache[event['jwt']] != true
      @logger.debug("JWT not authorised, event dropped")
      event.cancel
    else
      @logger.debug("JWT authorised")
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Auth0Jwt

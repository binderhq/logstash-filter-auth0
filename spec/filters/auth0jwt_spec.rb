# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/auth0jwt"

describe LogStash::Filters::Auth0 do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        auth0jwt {
          domain => "Hello World"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject).to include("message")
      expect(subject['message']).to eq('Hello World')
    end
  end
end

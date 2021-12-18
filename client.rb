require 'sinatra'
require 'rack-cas'
require 'rack/cas'

set :sessions, path: '/', secret: SecureRandom.hex(32) #, key: '__Host-Session', secure: true
use Rack::CAS, server_url: 'https://localhost:8081/cas', verify_ssl_cert: false

before do
  unless session['cas'] && session['cas']['user']
    halt 401, 'Unauthorized'
  end
  # unless ENV.fetch('API_ALLOW_USERS', 'user1').split(',').include?(session['cas']['user'])
  #   halt 403, 'User not in whitelist, go away :P'
  # end
end

get('/') do
  session['cas'].inspect
end

require 'sinatra'
require 'rack-cas'
require 'rack/cas'

set :sessions, path: '/', secret: SecureRandom.hex(32) #, key: '__Host-Session', secure: true
use Rack::CAS, server_url: 'https://localhost:8081/cas', verify_ssl_cert: false

before do
  if request.path != '/'
    unless session['cas'] && session['cas']['user']
      halt 401, 'Unauthorized'
    end
  end
  # unless ENV.fetch('API_ALLOW_USERS', 'user1').split(',').include?(session['cas']['user'])
  #   halt 403, 'User not in whitelist, go away :P'
  # end
end

get('/login') do
  '<a href=logout>logout here</a>' +
  session['cas'].inspect
end

get('/') do
  '<a href=/login>login here</a><br>' +
  '<a href=/logout>logout</a>'
end

get('/logout') do
  '<a href=/login>login here</a><br>' +
  '<a href=/>some other page</a>'
end

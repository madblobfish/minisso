require 'sinatra/base'
require 'webrick'
require 'webrick/https'
require 'securerandom'
require 'openssl'
require 'cgi'
require 'haml'

# load protocols and userbackends
Dir["./lib/{protocol,userbackend}/*.rb"].each {|file| require file }
$USERBACKEND = Object.const_get(ENV.fetch('MINICAS_USERBACKEND', 'RamUserBackend')).new

class MiniCAS < Sinatra::Base
  ENV.fetch('MINICAS_EXTENSIONS', ProtocolBase.implementations_str).split(':').each{|x| use Object.const_get(x)}

  # account/group managament
  get('/') do
    haml :index
  end
  get('/qr.js') do
    [200, {'Content-Type'=>'application/javascript'}, File.read('./qr.js')]
  end
  post('/register') do
    halt 403, 'registration not open' unless $USERBACKEND.registration_open?
    halt 400, 'user missing' unless request['name']
    halt 400, 'password missing' unless request['pw']
    halt 400, 'user already taken' if $USERBACKEND.exists?(request['name']) && request['name'] != session['registration_name']
    if request['2fa'] == 'yes'
      $USERBACKEND.preregister(request['name'])
      session['registration_name'] = request['name']
      session['registration_password'] = request['pw']
      session['registration_secret'], url = $USERBACKEND.totp_new_secret
      haml :register_2fa
    else
      $USERBACKEND.register(request['name'], {pw:request['pw']})
      haml :register_success
    end
  end
  post('/register-verify-2fa') do
    halt 403, 'registration not open' unless $USERBACKEND.registration_open?
    halt 400, 'BLAH! do better' unless session['registration_secret']
    halt 400, '2FA-Token missing' unless request['2fa']
    if $USERBACKEND.totp_valid?(session['registration_secret'], request['2fa'])
      $USERBACKEND.register(
        session['registration_name'],
        {pw:session['registration_password'], totp:{s:session['registration_secret'], last:Time.now-5}}
      )
      haml :register_success
    else
      haml :register_bad
      $USERBACKEND.clear_preregister(session['registration_name']) if session['registration_name']
    end
  end

  get('/list-users') do
    $USERBACKEND.all.join('<br>')
  end

  set :sessions, secret: SecureRandom.hex(32), key: '__Host-Session', path: '/', secure: true
end

Rack::Handler::WEBrick.run MiniCAS, **{
  :DocumentRoot   => '/tmp/no',
  :Port           => 8081,
  :SSLEnable      => true,
  :SSLCertificate => OpenSSL::X509::Certificate.new(File.read('./server.pem')),
  :SSLPrivateKey  => OpenSSL::PKey::RSA.new(        File.read('./server.key')),
  :SSLCertName    => [['CN', 'localhost']]
}

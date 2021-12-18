require 'sinatra/base'
require 'webrick'
require 'webrick/https'
require 'securerandom'
require 'openssl'

# load protocols and userbackends
Dir["./lib/{protocol,userbackend}/*.rb"].each {|file| require file }
$USERBACKEND = Object.const_get(ENV.fetch('MINICAS_USERBACKEND', 'RamUserBackend')).new

class MiniCAS < Sinatra::Base
  ENV.fetch('MINICAS_EXTENSIONS', ProtocolBase.implementations_str).split(':').each{|x| use Object.const_get(x)}

  # account/group managament
  get('/') do
    return 'hi, sadly registration is not open' unless $USERBACKEND.registration_open?
    '<h2>Register?</h2><form method=post action=/register>' +
      '<input name=name  autofocus placeholder=user><br><input name=pw type=password placeholder=password><br>' +
      '<label>2FA<input name=2fa type=checkbox value=yes></label><br><input type=submit>' +
    '</form>'
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
      '<style>svg{width:400px}</style><a href="'+url+'">TODO QRCODE HERE</a><br><br>' +
      '<form method=post action=/register-verify-2fa>' +
        '<input name=2fa autofocus placeholder=2FA-Token><br><input type=submit>' +
      '</form><script src=/qr.js></script>'
    else
      $USERBACKEND.register(request['name'], {pw:request['pw']})
      'yo gotta account'
    end
  end
  post('/register-verify-2fa') do
    halt 403, 'registration not open' unless $USERBACKEND.registration_open?
    halt 400, 'BLAH! do better' unless session['registration_secret']
    halt 400, '2FA-Token missing' unless request['2fa']
    if totp_valid?(session['registration_secret'], request['2fa'])
      $USERBACKEND.register(
        session['registration_name'],
        {pw:session['registration_password'], totp:{s:session['registration_secret'], last:Time.now-5}}
      )
      'sucessifullies'
    else
      'bad 2FA-Token, <a href=/>try again</>'
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


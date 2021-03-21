# https://apereo.github.io/cas/6.3.x/protocol/CAS-Protocol-Specification.html

require 'sinatra/base'
require 'webrick'
require 'webrick/https'
require 'openssl'

require 'securerandom'
require 'sinatra'
require 'rotp'

TICKETS = ObjectSpace::WeakMap.new

def totp_valid?(secret, token, after=Time.now-60)
  ROTP::TOTP.new(secret).verify(token, drift_behind: 15, after: after)
end
def ticket_make(username, service, time=Time.now)
  rnd = 'ST-'+SecureRandom.alphanumeric(28)
  TICKETS[rnd] = {t:time, u:username, s:service}
  rnd
end
def ticket_validate(ticket, service, time=Time.now)
  if (t = TICKETS[ticket])
    TICKETS.delete(ticket)
    return false if t[:t] + 15 > time
    return t[:u] unless t[:s] == service
  end
  false
end
def ticket_redir(username, service)
service+'?ticket='+ticket_make(username,service)
end

class MiniCAS < Sinatra::Base
  USERS = {"asd":{pw:"asd"}}
  get('/login') do # credential requestor / acceptor
    session['renew'] = request['renew']
    session['gateway'] = request['gateway'] unless session['renew'] # never show
    if session['loggedin'] && !session['renew']
      return redirect(ticket_redir(session['username'],request['service'])) if request['service']
      return 'already logged in'
    end
    return redirect(session['service']) if session['gateway'] && session['service']
    session['service'] = request['service']
    # session['method'] = request['method'] # method to use for
    # session['warn'] = request['warn'] # client must be prompted before being authenticated
    '<a href=/>Acc over her</a>' +
    '<form method=post action=/login>' +
      '<input name=username autofocus placeholder=user><br><input name=password type=password placeholder=password><br>' +
      '<input name=2fa placeholder=2FA-Token><br><input type=submit>' +
      # dunno why to do this
      # (session['service'] ? '<input name=service type=hidden value="'+CGI::escapeHTML(session['service'])+'">' : '') +
    '</form>'
  end
  post('/login') do
    halt 400, 'user missing' unless request['username']
    halt 400, 'password missing' unless request['password']
    usr = USERS.fetch(request['username'], {pw:'nnnnnnnnnnnnnnn', totp:{s:'base32secret'},last:Time.now})
    authfail = request['password'] != usr[:pw]
    authfail ||= request['2fa'] != '' && !totp_valid?(usr.fetch(:totp,{s:''})[:s], request['2fa'], usr.fetch(:totp,{time:Time.now})[:time])
    halt 400, 'stahp' if authfail
    USERS[request['username']][:totp][:last] = Time.now if request['2fa'] != ''
    session['loggedin'] = true
    session['username'] = request['username']
    return redirect(ticket_redir(session['username'],session['service'])) if session['service']
    'logged in'
  end
  get('/logout') do # destroy CAS session (logout)
    session.delete('loggedin')
    'loggeddyouty'
  end
  get('/validate') do # service ticket validation
    p request
    halt 400, 'no' unless request['service']
    halt 400, 'no' unless request['ticket']
    u = ticket_validate(request['ticket'], request['service'])
    p u
    return [200, {}, "yes\n#{u}"] if u
    [200, {}, "no"]
  end
  get('/serviceValidate') do # service ticket validation
    u = ticket_validate(request['ticket'], request['service'])
    case (request['format'] || 'xml').downcase
    when "xml"
      if u
        [200, {'Content-Type'=>'application/xml'}, StringIO.new('<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>'+u+'</cas:user><cas:attributes></cas:attributes></cas:authenticationSuccess></cas:serviceResponse>')]
      else
        [200, {'Content-Type'=>'application/xml'}, StringIO.new('<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationFailure code="INVALID_TICKET"></cas:authenticationFailure></cas:serviceResponse>')]
      end
    when "json"
      if u
        [200, {'Content-Type'=>'application/json'}, StringIO.new('{"serviceResponse": "authenticationSuccess":{"user":"'+u+'","attributes":{}}}')]
      else
        [200, {'Content-Type'=>'application/xml'}, StringIO.new('{"serviceResponse":"authenticationFailure":{"code":"INVALID_TICKET","description":""}}')]
      end
    else
      [200, {'Content-Type'=>'application/xml'}, StringIO.new('<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationFailure code="INTERNAL_ERROR"></cas:authenticationFailure></cas:serviceResponse>')]
    end
  end
  # get('/proxyValidate') do # service/proxy ticket validation [CAS 2.0]
  #   halt 500, 'no'
  # end
  # get('/proxy') do # proxy ticket service [CAS 2.0]
  # end
  # get('/p3/serviceValidate') do # service ticket validation [CAS 3.0]
  # end
  # get('/p3/proxyValidate') do # service/proxy ticket validation [CAS 3.0]
  # end
  ##
  # joshida senshai
  # https://en.wikipedia.org/wiki/Naoki_Yamamoto_%28manga_artist%29


  # account stuffs
  get('/') do
    '<h2>Register?</h2><form method=post action=/register>' +
      '<input name=name  autofocus placeholder=user><br><input name=pw type=password placeholder=password><br>' +
      '<label>2FA<input name=2fa type=checkbox value=yes></label><br><input type=submit>' +
    '</form>'
  end
  get('/qr.js') do
    [200, {'Content-Type'=>'application/javascript'}, File.read('./qr.js')]
  end
  post('/register') do
    halt 400, 'user missing' unless request['name']
    halt 400, 'password missing' unless request['pw']
    USERS.delete(request['name']) if USERS[request['name']].is_a?(Time) && USERS[request['name']]+120 <= Time.now
    halt 400, 'user already taken' if USERS[request['name']] && request['name'] != session['registration_name']
    if request['2fa'] == 'yes'
      USERS[request['name']] = Time.now # block for 5min
      session['registration_name'] = request['name']
      session['registration_password'] = request['pw']
      session['registration_secret'] = secret = ROTP::Base32.random
      url = ROTP::TOTP.new(secret).provisioning_uri("MINICAS")
      '<style>svg{width:400px}</style><a href="'+url+'">TODO QRCODE HERE</a><br><br>' +
      '<form method=post action=/register-verify-2fa>' +
        '<input name=2fa autofocus placeholder=2FA-Token><br><input type=submit>' +
      '</form><script src=/qr.js></script>'
    else
      USERS[request['name']] = {pw:request['pw']}
      'yo gotta account'
    end
  end
  post('/register-verify-2fa') do
    halt 400, 'BLAH! do better' unless session['registration_secret']
    halt 400, '2FA-Token missing' unless request['2fa']
    if totp_valid?(session['registration_secret'], request['2fa'])
      USERS[session['registration_name']] = {pw:session['registration_password'],totp:{s:session['registration_secret'],last:Time.now-5}}
      'sucessifullies'
    else
      'bad 2FA-Token, <a href=/>try again</>'
      USERS.delete(session['registration_name']) if session['registration_name']
    end
  end

  get('/list-users') do
    USERS.map{|k,v| "#{k}#{'*' if v.is_a?(Time)}"}.join('<br>')
  end

  set :sessions, secret: SecureRandom.hex(32) #, key: '__Host-Session', path: '/', secure: true
end

Rack::Handler::WEBrick.run MiniCAS, **{
  :DocumentRoot   => '/tmp/no',
  :Port           => 8081,
  :SSLEnable      => true,
  :SSLCertificate => OpenSSL::X509::Certificate.new(File.read('./server.pem')),
  :SSLPrivateKey  => OpenSSL::PKey::RSA.new(        File.read('./server.key')),
  :SSLCertName    => [['CN', 'localhost']]
}


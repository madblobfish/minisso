# https://apereo.github.io/cas/6.3.x/protocol/CAS-Protocol-Specification.html
require_relative 'base.rb'
require 'securerandom'

class CAS < ProtocolBase
  def initialize(app = nil)
    super
    @cas_tickets = {}
  end
  def ticket_make(username, service, time=Time.now)
    rnd = 'ST-'+SecureRandom.alphanumeric(28)
    @cas_tickets[rnd] = {t:time, u:username, s:service}
    if @cas_tickets.length >= 100
      @cas_tickets.keys[50..-1].each{|k|@cas_tickets.delete(k)}
    end
    @cas_tickets.keys
    rnd
  end
  def ticket_validate(ticket, service, time=Time.now)
    return false unless (t = @cas_tickets.delete(ticket))
    return false unless (t[:t] + 15) > time
    return t[:u] if t[:s] == service
    false
  end
  def ticket_redir(username, service)
    service+'?ticket='+ticket_make(username,service)
  end

  def service_blocked?(service)
    @hosts_allow ||= ENV.fetch('CAS_HOSTS_ALLOW', '').split(',')
    @hosts_block ||= ENV.fetch('CAS_HOSTS_BLOCK', '').split(',')
    @proto_allow ||= ENV.fetch('CAS_PROTO_ALLOW', 'http,https').split(',')
    uri = URI(service)
    return true unless @proto_allow.any?{|p| uri.scheme == p}
    return true if @hosts_block.any?{|h| uri.host == h}
    ! @hosts_allow.any?{|h| uri.host == h}
  end

  namespace('/cas') do
    get('/tickets') do
      halt 404 if settings.production?
      @cas_tickets.map{|k,v| "#{k} -> {time: #{v[:t]}, user: #{v[:u]}, service: #{v[:s]}}" }.join('<br>')
    end

    get('/sessions') do
      return 'login first' unless session['loggedin']
      session['cas_seen_services']&.join('<br>')
    end

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
      haml :login
    end
    post('/login') do
      halt 400, 'user missing' unless request['username']
      halt 400, 'password missing' unless request['password']
      authfail = !$USERBACKEND.check_pw(request['username'], request['password'])
      authfail ||= request['2fa'] != '' && !$USERBACKEND.check_totp(request['username'], request['2fa'])
      halt 400, 'stahp' if authfail
      $USERBACKEND.update_last_login(request['username']) if request['2fa'] != ''
      session['loggedin'] = true
      session['username'] = request['username']
      if session['service']
        session['cas_seen_services'] ||= Set.new
        session['cas_seen_services'] << session['service']
        return redirect(ticket_redir(session['username'], session['service']))
      end
      'logged in'
    end
    get('/logout') do # destroy CAS session (logout)
      services_triggered = []
      session.fetch('cas_seen_services', []).each do |s|
        services_triggered << s
      end
      session.delete('loggedin')
      return 'loggeddyouty completely' if services_triggered.empty?
      'loggeddyouty but not from some services: ' + services_triggered.join(', ')
    end
    get('/validate') do # service ticket validation
      halt 404, 'this looked unused, sorry'
      halt 400, 'no' unless request['service']
      halt 400, 'no' if service_blocked?(request['service'])
      halt 400, 'no' unless request['ticket']
      u = ticket_validate(request['ticket'], request['service'])
      return [200, {}, "yes\n#{u}"] if u
      [200, {}, 'no']
    end
    get('/serviceValidate') do # service ticket validation
      halt 400, 'no' unless request['service']
      halt 400, 'no' if service_blocked?(request['service'])
      u = ticket_validate(request['ticket'], request['service'])
      case (request['format'] || 'xml').downcase
      when 'xml'
        if u
          [200, {'Content-Type'=>'application/xml'}, StringIO.new('<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>'+u+'</cas:user><cas:attributes></cas:attributes></cas:authenticationSuccess></cas:serviceResponse>')]
        else
          [200, {'Content-Type'=>'application/xml'}, StringIO.new('<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationFailure code="INVALID_TICKET"></cas:authenticationFailure></cas:serviceResponse>')]
        end
      when 'json'
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
  end
end

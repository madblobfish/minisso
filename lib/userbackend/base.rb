require 'rotp'

class UserBackendBase
  def initialize(**opts)
    @registration_open = opts.fetch(:registration_open, true)
  end
  def registration_open?
    @registration_open
  end

  def registration_close
    @registration_open = false
  end
  def registration_open
    @registration_open = true
  end

  # totp
  def totp_new_secret
    secret = ROTP::Base32.random
    [secret, ROTP::TOTP.new(secret).provisioning_uri("MINICAS")]
  end
  def totp_valid?(secret, token, after=Time.now-60)
    ROTP::TOTP.new(secret).verify(token, drift_behind: 15, after: after)
  end
  def check_totp(name, totp)
    usr = fetch(name, {})
    secret = usr.fetch(:totp, {s:'base32secret'})[:s]
    last = usr.fetch(:totp, {}).fetch(:last, Time.now-60)
    totp_valid?(secret, totp, last)
  end
end

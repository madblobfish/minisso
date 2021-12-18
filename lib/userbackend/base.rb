require 'rotp'

class UserBackendBase
  def initialize(**opts)
    @registration_open = opts.fetch(:registration_open, true)
  end
  def registration_open?
    @registration_open
  end

  # totp
  def totp_valid?(secret, token, after=Time.now-60)
    ROTP::TOTP.new(secret).verify(token, drift_behind: 15, after: after)
  end
  def totp_new_secret
    secret = ROTP::Base32.random
    [secret, ROTP::TOTP.new(secret).provisioning_uri("MINICAS")]
  end
end

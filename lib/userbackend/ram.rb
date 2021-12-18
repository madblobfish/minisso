class RamUserBackend < UserBackendBase
  def initialize(**opts)
    @users = {"asd":{pw:"asd"}}
    super
  end
  def all
    @users.map{|k,v| "#{k}#{'*' if v.is_a?(Time)}"}
  end

  def exists?(name)
    clear_old_preregister(name)
    @users.key?(name)
  end
  def fetch(*args)
    clear_old_preregister(args.first)
    @users.fetch(*args)
  end
  def check_totp(name, totp)
    usr = fetch(name, {totp:{s:'base32secret'},last:Time.now})
    secret = usr.fetch(:totp,{s:'base32secret'})[:s]
    time = usr.fetch(:totp,{time:Time.now})[:time]
    totp_valid?(secret, request['2fa'], time)
  end
  def check_pw(name, pw)
    @users.fetch(name, {pw:'nnnnnnnnnnnnnnn'})[:pw] == pw
  end
  def preregister(name)
    @users[name] = Time.now
  end
  def register(name, contents)
    @users[name] = contents
  end
  def clear_old_preregister(name)
    @users.delete('name') if @users['name'].is_a?(Time) && @users['name']+120 <= Time.now
  end
  def clear_preregister(name)
    @users.delete('name') if @users['name'].is_a?(Time)
  end
end

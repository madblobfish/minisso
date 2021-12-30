class RamUserBackend < UserBackendBase
  def initialize(**opts)
    @users = {
      "asd"=>{pw:"asd"},
      "qwe"=>{pw:"qwe", totp:{last:Time.now, s:"FWKAKWNXUEHPIX5ZMTXRY7UJTNEDUPPF"}}
    }
    super
  end
  def all
    @users.map{|k,v| "#{k}#{'*' if v.is_a?(Time)}"}
  end

  def preregister(name)
    # block username from being registered
    @users[name] = Time.now
  end
  def clear_old_preregister(name)
    @users.delete('name') if @users['name'].is_a?(Time) && @users['name']+120 <= Time.now
  end
  def clear_preregister(name)
    @users.delete('name') if @users['name'].is_a?(Time)
  end
  def register(name, contents)
    @users[name] = contents
  end
  def exists?(name)
    clear_old_preregister(name)
    @users.key?(name)
  end
  def fetch(*args)
    clear_old_preregister(args.first)
    @users.fetch(*args)
  end
  def check_pw(name, pw)
    return false unless @users.key?(name)
    @users[name][:pw] == pw
  end
  def update_last_login(name)
    @users[name][:totp][:last] = Time.now
  end
  def cas_add_service(name, service)
    @users[name][:cas_services] ||= []
    @users[name][:cas_services] << value
  end
  def fetch_attr(name, *args)
    @users[name].fetch(*args)
  end
end

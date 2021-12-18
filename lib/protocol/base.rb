require 'sinatra/base'

class ProtocolBase < Sinatra::Base
  def self.inherited(subclass)
    super
    @implementations ||= []
    @implementations << subclass
  end

  def self.implementations
    @implementations
  end
  def self.implementations_str
    implementations.join(':')
  end
end

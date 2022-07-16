require 'sinatra/base'
require 'sinatra/namespace'
require 'sinatra/content_for'

class ProtocolBase < Sinatra::Base
  register Sinatra::Namespace
  helpers Sinatra::ContentFor
  set :views, __dir__ + '/../../views'
  set :haml, :layout => :base
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

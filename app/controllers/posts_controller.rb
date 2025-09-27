class PostsController < ApplicationController
  include Secured

  def index
    @user = session[:userinfo]
  end
end

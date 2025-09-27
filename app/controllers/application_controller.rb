class ApplicationController < ActionController::Base
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  allow_browser versions: :modern

  # Changes to the importmap will invalidate the etag for HTML responses
  stale_when_importmap_changes

  helper_method :current_user, :user_signed_in?

  private

    def current_user
      @current_user ||= User.find_by(id: session[:user_id])
    end

    def user_signed_in?
      current_user.present?
    end

    def authenticate_user!
      unless user_signed_in?
        session[:return_to] = request.fullpath # Remember where they were trying to go
        redirect_to root_path, alert: "You must sign in first"
      end
    end
end

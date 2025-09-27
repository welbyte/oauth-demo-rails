class Auth0Controller < ApplicationController
  def callback
    if @user = User.from_omniauth(request.env["omniauth.auth"])
      session[:user_id] = @user.id
    end

    redirect_to after_sign_in_url
  end

  def failure
    # Handles failed authentication -- Show a failure page (you can also handle with a redirect)
    @error_msg = request.params["message"]
  end

  def logout
    reset_session
    redirect_to logout_url, allow_other_host: true
  end

  private

    def after_sign_in_url
      posts_url
    end

    def logout_url
      request_params = {
        returnTo: root_url,
        client_id: AUTH0_CONFIG["auth0_client_id"]
      }

      URI::HTTPS.build(host: AUTH0_CONFIG["auth0_domain"], path: "/v2/logout", query: request_params.to_query).to_s
    end
end

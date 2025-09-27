AUTH0_CONFIG = Rails.application.config_for(:auth0)

Rails.application.config.middleware.use OmniAuth::Builder do
  provider(
    :auth0,
    AUTH0_CONFIG["auth0_client_id"],
    AUTH0_CONFIG["auth0_client_secret"],
    AUTH0_CONFIG["auth0_domain"],
    callback_path: "/auth/auth0/callback",
    authorize_params: {
      scope: "openid email profile"
    },
    provider_ignores_state: true,
    setup: lambda do |env|
      request = Rack::Request.new(env)
      organization = request.params["organization"]
      screen_hint = request.params["screen_hint"]

      if organization.present?
        env["omniauth.strategy"].options[:authorize_params][:organization] = organization
      end
      
      if screen_hint.present?
        env["omniauth.strategy"].options[:authorize_params][:screen_hint] = screen_hint
      end
    end
  )
end

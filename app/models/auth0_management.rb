class Auth0Management
  def initialize
    @client ||= Rails.application.config.x.auth0_client
  end

  def get_user_organization(user_id)
    return nil unless user_id.present?

    organizations = @client.get_user_organizations(user_id)
    return nil if organizations.empty?

    org = organizations.first

    {
      id: org["id"],
      name: org["name"],
      display_name: org["display_name"] || org["name"],
      logo_url: org["branding"]&.dig("logo_url")
    }
  rescue Auth0::Exception => e
    Rails.logger.error "Auth0 Management API error: #{e.message}"
    nil
  end
end

class User < ApplicationRecord
  def self.from_omniauth(auth)
    where(provider: auth.provider, uid: auth.uid).first_or_create do |user|
      user.email = auth.info.email
    end
  end

  def organization
    Rails.cache.fetch("user_#{uid}_organization") do
      Auth0Management.new.get_user_organization(uid)
    end
  end
end

class Current < ActiveSupport::CurrentAttributes
  attribute :organization, :user

  def user=(user)
    super
    self.organization = user.organization
  end
end

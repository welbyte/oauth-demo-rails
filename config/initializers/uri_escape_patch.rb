# Compatibility patch for URI.escape which was deprecated in Ruby 2.7 and removed in Ruby 3.0
# The auth0 gem still uses URI.escape, so we need to provide a compatibility layer

require "erb"

module URI
  def self.escape(str)
    # ERB::Util.url_encode(str)
    str
  end

  def self.unescape(str)
    CGI.unescape(str)
  end
end

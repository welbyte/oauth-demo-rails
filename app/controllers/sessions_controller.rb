require "net/http"

class SessionsController < ApplicationController
  skip_forgery_protection only: :show

  AUTH_ENDPOINT  = "https://accounts.google.com/o/oauth2/v2/auth"
  TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
  JWKS_URI       = "https://www.googleapis.com/oauth2/v3/certs"
  ISSUER         = "https://accounts.google.com"

  def create
    state     = SecureRandom.hex(16)
    nonce     = SecureRandom.hex(16)
    verifier  = base64url(SecureRandom.random_bytes(32))
    challenge = base64url(sha256(verifier))

    session[:oidc_state]         = state
    session[:oidc_nonce]         = nonce
    session[:pkce_code_verifier] = verifier

    params = {
      response_type: "code",
      client_id:     ENV.fetch("GOOGLE_CLIENT_ID"),
      redirect_uri:  redirect_uri,
      scope:         "openid email profile",
      state:         state,
      nonce:         nonce,
      code_challenge:        challenge,
      code_challenge_method: "S256",
      prompt:        "select_account"
    }

    redirect_to "#{AUTH_ENDPOINT}?#{URI.encode_www_form(params)}", allow_other_host: true, status: :see_other
  end

  def show
    # 1) CSRF state check
    unless secure_compare(params[:state].to_s, session.delete(:oidc_state).to_s)
      return redirect_to root_path, alert: "Invalid state"
    end

    # 2) Exchange code for tokens
    code = params[:code]
    token_json = http_post_form(TOKEN_ENDPOINT, {
      grant_type:    "authorization_code",
      code:          code,
      redirect_uri:  redirect_uri,
      client_id:     ENV.fetch("GOOGLE_CLIENT_ID"),
      client_secret: ENV["GOOGLE_CLIENT_SECRET"], # confidential web client
      code_verifier: session.delete(:pkce_code_verifier)
    })
    id_token = token_json["id_token"] or return redirect_to root_path, alert: "No id_token"

    # 3) Verify ID token (sig + claims)
    header_b64, payload_b64, sig_b64 = id_token.split(".")
    header  = JSON.parse(base64url_decode(header_b64))
    payload = JSON.parse(base64url_decode(payload_b64))
    sig     = base64url_decode(sig_b64)

    Rails.logger.debug("Payload: #{payload}")

    jwk = fetch_jwk(header["kid"])
    public_key = jwk_to_rsa(jwk)
    data = [ header_b64, payload_b64 ].join(".")
    ok = public_key.verify(OpenSSL::Digest::SHA256.new, sig, data)
    return redirect_to root_path, alert: "Bad signature" unless ok

    iss_ok   = (payload["iss"] == ISSUER || payload["iss"] == "accounts.google.com")
    aud_ok   = Array(payload["aud"]).include?(ENV.fetch("GOOGLE_CLIENT_ID"))
    exp_ok   = payload["exp"].to_i > Time.now.to_i - 30
    nonce_ok = payload["nonce"].to_s == session.delete(:oidc_nonce).to_s
    unless iss_ok && aud_ok && exp_ok && nonce_ok
      return redirect_to root_path, alert: "Invalid token claims"
    end

    # 4) Create session
    user = User.find_or_create_by(provider: "google", uid: payload["sub"]) do |u|
      u.email = payload["email"]
      u.name  = payload["name"] || [ payload["given_name"], payload["family_name"] ].compact.join(" ")
    end

    return_to = session[:return_to]
    reset_session
    session[:user_id] = user.id
    redirect_to(return_to || root_path, notice: "Signed in")
  rescue => e
    Rails.logger.error("Google OIDC error: #{e.class}: #{e.message}")
    redirect_to root_path, alert: "Sign-in failed"
  end

  def destroy
    reset_session
    redirect_to root_path, notice: "Signed out"
  end

  private

  def http_post_form(url, form_hash)
      uri = URI(url)
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        http.read_timeout = 5
        req = Net::HTTP::Post.new(uri)
        req["Content-Type"] = "application/x-www-form-urlencoded"
        req.body = URI.encode_www_form(form_hash)
        http.request(req)
      end
      raise "HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess)
      JSON.parse(res.body)
    end

    def http_get_json(url)
      uri = URI(url)
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        http.read_timeout = 5
        http.request(Net::HTTP::Get.new(uri))
      end
      raise "HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess)
      JSON.parse(res.body)
    end

    def fetch_jwk(kid)
      cache = Rails.cache.fetch("google_jwks", expires_in: 1.hour) do
        http_get_json(JWKS_URI)
      end
      key = cache["keys"].find { |k| k["kid"] == kid }
      # If rotating keys, refetch once if not found
      unless key
        cache = http_get_json(JWKS_URI)
        Rails.cache.write("google_jwks", cache, expires_in: 1.hour)
        key = cache["keys"].find { |k| k["kid"] == kid }
      end
      raise "JWK not found for kid=#{kid}" unless key
      key
    end

    def jwk_to_rsa(jwk)
      n_bn = OpenSSL::BN.new(base64url_decode(jwk["n"]), 2)
      e_bn = OpenSSL::BN.new(base64url_decode(jwk["e"]), 2)

      rsa_seq = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Integer(n_bn),
        OpenSSL::ASN1::Integer(e_bn)
      ])

      alg_id = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId("rsaEncryption"),
        OpenSSL::ASN1::Null(nil)
      ])

      spki = OpenSSL::ASN1::Sequence([
        alg_id,
        OpenSSL::ASN1::BitString(rsa_seq.to_der)
      ])

      OpenSSL::PKey.read(spki.to_der)  # => OpenSSL::PKey::RSA public key
    end

    def sha256(bytes) = OpenSSL::Digest::SHA256.digest(bytes)

    def base64url(str) = Base64.urlsafe_encode64(str).delete("=")

    def base64url_decode(str)
      str += "=" * ((4 - str.length % 4) % 4)
      Base64.urlsafe_decode64(str)
    end

    def redirect_uri
      ENV.fetch("GOOGLE_REDIRECT_URI") # e.g. http://localhost:3000/google_session
    end

    # constant-time string compare
    def secure_compare(a, b)
      return false if a.bytesize != b.bytesize
      l = a.unpack("C*")
      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      res == 0
    end
end

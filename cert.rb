class Cert
  def generate(options = {})
    country = options["country"] || "US"
    org = options[:org] ||= "Test"
    org_unit = options[:org_unit] ||= "Test"
    common_name = options[:common_name] ||= "Test"
    ca = options[:ca].nil? ? true : options[:ca]
    duration = options[:duration] || 365
    client = options[:client] || false
    name = options[:name] || "test"
    use_ca = options[:use_ca]

    if use_ca
      ca_cert, ca_key = use_ca
    end

    key = OpenSSL::PKey::RSA.new(4096)
    private_key = key.export

    File.write("#{name}-key.pem", key.export)

    public_key = key.public_key

    subject = "/C=#{country}/O=#{org}/OU=#{org_unit}/CN=#{common_name}"

    cert = OpenSSL::X509::Certificate.new
    cert.subject = OpenSSL::X509::Name.parse(subject)
    if ca_cert && ca_key
        cert.issuer = ca_cert.subject
    else
        cert.issuer = cert.subject
    end

    cert.not_before = Time.now - 24 * 60 * 60
    cert.not_after = Time.now + duration * 24 * 60 * 60
    cert.public_key = public_key
    cert.serial = Time.now.to_i
    cert.version = 2

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    if ca_cert && ca_key
        ef.issuer_certificate = ca_cert
    else
        ef.issuer_certificate = cert
    end
    cert.extensions = [
      ef.create_extension("subjectKeyIdentifier", "hash")
    ]


    cert.add_extension(ef.create_extension("basicConstraints","CA:TRUE", true)) if ca
    cert.add_extension(ef.create_extension("keyUsage", "keyCertSign", true)) if ca

    cert.add_extension(ef.create_extension("extendedKeyUsage", "clientAuth")) if client || ca
    cert.add_extension(ef.create_extension("extendedKeyUsage", "serverAuth")) 
    
    cert.add_extension(ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")) if ca


    if ca_cert && ca_key
      cert.sign(ca_key, OpenSSL::Digest::SHA256.new)
    else
      cert.sign key, OpenSSL::Digest::SHA256.new
    end

    File.write("#{name}-cert.pem", cert.to_pem)


    [cert, key]
  end
end
local asn1 = require "asn1"
local bin = require "bin"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local tls = require "tls"
local url = require "url"

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"external", "safe"}

local oid_sha1 = string.char(1, 3, 14, 3, 2, 26)

portrule = shortport.ssl

local match_dn = function(dn1, dn2)
  if #dn1 ~= #dn2 then
    return false
  end

  for key, val in pairs(dn1) do
    if dn2[key] ~= val then
      return false
    end
  end

  return true
end

local find_alt_names = function(dn, intermediate)
  if not interediate.extensions then
    return false
  end

  for _, ext in ipairs(intermediate.extensions) do
    if ext.name == "X509v3 Subject Alternative Name" then
      if match_dn(dn, ext.value) then
        return true
      end
    end
  end

  return false
end

local find_issuer = function(cert, intermediates)
  -- We cannot trust that the intermediate certificates are ordered in any way,
  -- so search through each one to find one that matches the server certificate.
  for _, intermediate in ipairs(intermediates) do
    if match_dn(cert.issuer, intermediate.subject) then
      return intermediate
    end

    if match_alt_names(cert.issuer, intermediate) then
      return intermediate
    end
  end

  return
end

local ocsp_req = function(cert, intermediates, uri_str)
  -- Many certificates will be the same on a given host or set of
  -- hosts, so check the OCSP cache before querying, and return it if
  -- found.
  if not nmap.registry.ocsp then
    nmap.registry.ocsp = {}
  end

  local fingerprint = cert:digest("sha1")
  local cached_resp = nmap.registry.ocsp[fingerprint]
  if cached_resp then
    return cached_resp
  end

  -- Check if we support the protocol.
  uri = url.parse(uri_str)
  if url == "" then
    stdnse.debug1("Failed to parse OCSP responder URI: %s", uri_str)
    return
  end

  local port = nil
  if uri.scheme == "http" then
    port = uri.port or 80
  elseif uri.scheme == "https" then
    port = uri.port or 443
  else
    stdnse.debug1("Unsupported scheme '%s' in OCSP responder URI: %s", uri.scheme, uri_str)
    return
  end

  -- CertID          ::=     SEQUENCE {
  --     hashAlgorithm       AlgorithmIdentifier,
  --     issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
  --     issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
  --     serialNumber        CertificateSerialNumber }

  local issuer = find_issuer(cert, intermediates)
  if not issuer then
    -- Note that due to the unordered nature of the issuer table, it is unlikely
    -- that this name will output correctly. It will be readable enough, though.
    issuer = {}
    for key, val in pairs(cert.issuer) do
      table.insert(issuer, ("%s=%s"):format(key, val))
    end

    stdnse.debug1("Unable to find issuer certificate: %s", table.concat(issuer, ", "))
    return cert.issuer
  end

  -- For the issuerNameHash and the issuerKeyHash we require the raw
  -- DER encoding, not the parsed values.
  local der = cert.der
  local dec = asn1.ASN1Decoder:new()
  dec:registerBaseDecoders()
  dec:setStopOnError(true)

  stdnse.debug1(stdnse.tohex(der:sub(1, 10), {separator = ":"}))
  local pos, seq = dec:decode(der)

  --local iname = cert.raw.issuer
  --local ikey = issuer.raw.public_key
  local enc = asn1.ASN1Encoder:new()
  local inh = enc:encode(openssl.digest("sha1", iname))
  stdnse.debug1("I --> %d [%s]", #iname, stdnse.tohex(iname, {separator = ":"}))
  stdnse.debug1("I --> %s", stdnse.tohex(inh, {separator = ":"}))

  -- Create the OCSP request.
  local enc = asn1.ASN1Encoder:new()
  local alg = enc:encode_oid_component(oid_sha1)
  local inh = enc:encode(openssl.digest("sha1", iname))
  local ikh = enc:encode(openssl.digest("sha1", ikey))
  local ser = enc:encodeBigNum(cert.serial_number)
  local cid = enc:encodeSeq(alg .. inh .. ikh .. ser)
  local lst = enc:encodeSeq(cid)
  local tbs = enc:encodeSeq(tbs)
  local req = enc:encodeSeq(tbs)

  -- Send our OCSP request to the responder.
  -- local hdr = {["Content-Type"] = "application/ocsp-request"}
  -- local opt = {["header"] = hdr}
  -- local res = http.post(uri.host, port, uri.path, opt, req)
  -- if response.status ~= 200 then
  --   stdnse.debug1("DUN GOOFED!")
  --   return
  -- end

  return true
end

action = function(host, port)
  host.targetname = tls.servername(host)

  -- Get SSL certificate.
  local status, cert, intermediates = sslcert.getCertificate(host, port)
  if not status then
    stdnse.debug1("sslcert.getCertificate error: %s", cert)
    return
  end

  stdnse.debug1("1 --> %s", type(cert))
  stdnse.debug1("2 --> %d", #intermediates)
  for _, im in ipairs(intermediates) do
    issuer = {}
    for key, val in pairs(im.issuer) do
      table.insert(issuer, ("%s=%s"):format(key, val))
    end

    stdnse.debug1("3 --> %s", table.concat(issuer, ", "))
  end

  -- Check for the OCSP extension.
  local aia = nil
  for _, ext in ipairs(cert.extensions) do
    if ext.name == "Authority Information Access" then
      aia = ext.value
      break
    end
  end

  if not aia then
    stdnse.debug1("No Authority Information Access extension found in certificate.")
    return
  end

  -- Parse location of OCSP responder from representation of extension
  -- provided by OpenSSL.
  local uri = nil
  local pat = "OCSP - URI:"
  for _, line in ipairs(stdnse.strsplit("\n", aia)) do
    if line:sub(1, #pat) == pat then
      uri = line:sub(#pat + 1)
      break
    end
  end

  if not uri then
    stdnse.debug1("Failed to find OCSP responder URI in Authority Information Access extension: [%s]", aia)
    return
  end

  -- Query the OCSP responder with the certificate's information.
  local result = ocsp_req(cert, intermediates, uri)
  if not result then
    return
  end

  return result
end

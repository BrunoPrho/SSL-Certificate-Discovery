
-- Copyright (C) 2021 Bruno Pairault 

-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local tls = require "tls"
local have_openssl, openssl = pcall(require, "openssl")
local base64 = require "base64"

description = [[
This function retrieves a server's SSL certificate and saves ip, hostname, port, protocol, certificate in PEM in the CSV file given in script_args('csv_output.basepath')` The function supposes the path of the CSV files exists and do not make use of LUA libraries not included in nmap.
]]

author = "Bruno Pairault"
license = "This code is license in the The GNU General Public License version 2 (GPLv2). The code relies on nmap libraries licensed separatly."
categories = { "default", "safe", "discovery" }
dependencies = {"https-redirect"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

action = function(host, port)
  local mutex = nmap.mutex( "discovery" )
  mutex "lock"
  if not nmap.registry.discovery then
    nmap.registry.discovery = {}
    nmap.registry.discovery.init_done = false 
    local file_name = 'output.csv'
    file_name = stdnse.get_script_args('csv_output.basepath')
    nmap.registry.discovery.file_name=file_name
  end
  if not have_openssl then
    stdnse.debug1("Error: The script requires `have_openssl` ")
    return false
  end
  if not nmap.registry.discovery.init_done then
    nmap.registry.discovery.init_done = true
    local file = io.open(nmap.registry.discovery.file_name, "w")  -- rewrite
    file:close()
  end
  mutex "done"

  local file = io.open(nmap.registry.discovery.file_name, "a")
  io.output(file)
  host.targetname = tls.servername(host)
  local status, cert_pem = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("Error: sslcert.getCertificate error: %s", cert_pem)
    return false
  end
  if host.targetname == nil then
    host.targetname = " "
  end
  b64= base64.enc(cert_pem.pem)
  sha1_cert= openssl.sha1(b64)
  hash64= base64.enc(sha1_cert)
  file:write(host.ip .. "," .. host.name .. "," .. host.targetname .. "," .. port.service .. "," .. port.protocol .. "," .. port.number .. "," .. hash64 .. "," .. b64)
  file:write('\n')
  file:close()
  return true
end  -- end action





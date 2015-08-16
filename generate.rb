#!/usr/bin/ruby

require 'rubygems'
require 'openssl'
require './cert'

# Generate a new CA
c = Cert.new

ca = c.generate(ca: true, common_name: "slurv-docker", name: "ca")
server = c.generate(ca: false, client: false, name: "server", common_name: "slurv-docker", use_ca: ca)
client = c.generate(ca: false, client: true, name: "client", common_name: "slurv-docker", use_ca: ca)
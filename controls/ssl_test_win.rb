# copyright: 2018, The Authors

title "sample section"

invalid_targets = attribute(
  'invalid_targets',
  value: [
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    '::'
  ],
  description: 'Array of IPv4 and IPv6 Addresses to exclude'
)

# Array of TCP ports to exclude from SSL checking. For example: [443, 8443]
exclude_ports = attribute(
  'exclude_ports',
  value: [],
  description: 'Array of TCP ports to exclude from SSL checking'
)

target_hostname = attribute(
  'target_hostname',
  value: command('hostname').stdout.strip,
  description: 'Target hostname to check'
)

# Find all TCP ports on the system, IPv4 and IPv6
# Eliminate duplicate ports for cleaner reporting and faster scans and sort the
# array by port number.
tcpports = port.protocols(/tcp/).entries.uniq.sort_by { |entry| entry['port'] }

#describe tcpports do
#  it { should_not eq '' }
#end

# Make tcpports an array of hashes to be passed to the ssl resource
tcpports = tcpports.map do |socket|
  params = { port: socket.port }
  # Add a host param if the listening address of the port is a valid/non-localhost IP
  params[:host] = socket.address unless invalid_targets.include?(socket.address)
  params[:socket] = socket
  params
end

# Filter out ports that don't respond to any version of SSL
sslports = tcpports.find_all do |tcpport|
  !exclude_ports.include?(tcpport[:port]) && ssl(tcpport).enabled?
end

#describe sslports do
#  it { should_not eq '' }
#end

# You can use this to display all the supported ciphers
#sslports.each do |sslport|
#  # create a description
#  proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
#  describe ssl(sslport).ciphers do
#    it { should_not eq '' }
#  end
#end

#return

# Troubleshooting control to show InSpec version and list
# discovered tcp ports and the ssl enabled ones. Always succeeds
control 'debugging' do
  title "Inspec::Version=#{Inspec::VERSION}"
  impact 0.0
  describe "tcpports=\n#{tcpports.join("\n")}" do
    it { should_not eq nil }
  end
  describe "sslports=\n#{sslports.join("\n")}" do
    it { should_not eq nil }
  end
end

#######################################################
# Protocol Tests                                      #
# Valid protocols are: tls1.2                         #
# Invalid protocols are : ssl2, ssl3, tls1.0, tls1.1  #
#######################################################
control 'ssl2' do
  title 'Disable SSL 2 from all exposed SSL ports.'
  impact 1.0
  only_if { sslports.length > 0 }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('ssl2') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'ssl3' do
  title 'Disable SSL 3 from all exposed SSL ports.'
  impact 1.0
  only_if { sslports.length > 0 }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('ssl3') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end


#######################################################
# Symmetric Encryption Method (Enc) Tests             #
# Valid Enc modes are:                                #
# AES256, AES128, AES256-GCM, AES128-GCM, CHACHA20    #
#######################################################

control 'enc-des' do
  title 'Disable DES, 3DES as ENC from all exposed SSL/TLS ports and versions.'
  impact 0.5
  only_if { sslports.length > 0 }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).ciphers(/(WITH_(\d*)(des))/i) do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

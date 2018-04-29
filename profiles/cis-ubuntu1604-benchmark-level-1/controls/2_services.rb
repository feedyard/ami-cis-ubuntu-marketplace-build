# Controls mapped to CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0 12-28-2017

control "cis benchmark 2.1.1_Ensure_chargen_services_are_not_enabled" do
  title "Ensure chargen services are not enabled"
  desc  "chargen is a network service that responds with 0 to 512 ASCII characters for each connection it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("chargen").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^chargen\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^chargen\s+/) }
    end
  end
end

control "cis benchmark 2.1.2_Ensure_daytime_services_are_not_enabled" do
  title "Ensure daytime services are not enabled"
  desc  "daytime is a network service that responds with the server's current date and time. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("daytime").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^daytime\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^daytime\s+/) }
    end
  end
end

control "cis benchmark 2.1.3_Ensure_discard_services_are_not_enabled" do
  title "Ensure discard services are not enabled"
  desc  "discard is a network service that simply discards all data it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("discard").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^discard\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^discard\s+/) }
    end
  end
end

control "cis benchmark 2.1.4_Ensure_echo_services_are_not_enabled" do
  title "Ensure echo services are not enabled"
  desc  "echo is a network service that responds to clients with the data sent to it by the client. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("echo").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^echo\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^echo\s+/) }
    end
  end
end

control "cis benchmark 2.1.5_Ensure_time_services_are_not_enabled" do
  title "Ensure time services are not enabled"
  desc  "time is a network service that responds with the server's current date and time as a 32 bit integer. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.\n\nRationale: Disabling this service will reduce the remote attack surface of the system."
  impact 1.0
  describe xinetd_conf.services("time").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^time\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^time\s+/) }
    end
  end
end

control "cis benchmark 2.1.6_Ensure_rsh_server_is_not_enabled" do
  title "Ensure rsh server is not enabled"
  desc  "The Berkeley rsh-server (rsh, rlogin, rexec) package contains legacy services that exchange credentials in clear-text.\n\nRationale: These legacy services contain numerous security exposures and have been replaced with the more secure SSH package."
  impact 1.0
  describe xinetd_conf.services("shell").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^shell\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^shell\s+/) }
    end
  end
  describe xinetd_conf.services("login").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^login\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^login\s+/) }
    end
  end
  describe xinetd_conf.services("exec").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^exec\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^exec\s+/) }
    end
  end
  describe xinetd_conf.services("rsh").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^rsh\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^rsh\s+/) }
    end
  end
  describe xinetd_conf.services("rlogin").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^rlogin\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^rlogin\s+/) }
    end
  end
  describe xinetd_conf.services("resec").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^resec\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^resec\s+/) }
    end
  end
end

control "cis benchmark 2.1.7_Ensure_talk_server_is_not_enabled" do
  title "Ensure talk server is not enabled"
  desc  "The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client (allows initiate of talk sessions) is installed by default.\n\nRationale: The software presents a security risk as it uses unencrypted protocols for communication."
  impact 1.0
  describe xinetd_conf.services("talk").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^talk\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^talk\s+/) }
    end
  end
  describe xinetd_conf.services("ntalk").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^ntalk\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^ntalk\s+/) }
    end
  end
end

control "cis benchmark 2.1.8_Ensure_telnet_server_is_not_enabled" do
  title "Ensure telnet server is not enabled"
  desc  "The telnet-server package contains the telnet daemon, which accepts connections from users from other systems via the telnet protocol.\n\nRationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow a user with access to sniff network traffic the ability to steal credentials. The ssh package provides an encrypted session and stronger security."
  impact 1.0
  describe xinetd_conf.services("telnet").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^telnet\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^telnet\s+/) }
    end
  end
end

control "cis benchmark 2.1.9_Ensure_tftp_server_is_not_enabled" do
  title "Ensure tftp server is not enabled"
  desc  "Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot machines from a boot server. The packages tftp and atftp are both used to define and support a TFTP server.\n\nRationale: TFTP does not support authentication nor does it ensure the confidentiality or integrity of data. It is recommended that TFTP be removed, unless there is a specific need for TFTP. In that case, extreme caution must be used when configuring the services."
  impact 1.0
  describe xinetd_conf.services("tftp").protocols(/.*/) do
    it { should be_disabled }
  end
  describe file("/etc/inetd.conf") do
    its("content") { should_not match(/^tftp\s+/) }
  end
  command("find /etc/inetd.d -type f -regex .\\*/.\\+").stdout.split.each do |entry|
    describe file(entry) do
      its("content") { should_not match(/^tftp\s+/) }
    end
  end
end

control "cis benchmark 2.1.10_Ensure_xinetd_is_not_enabled" do
  title "Ensure xinetd is not enabled"
  desc  "The eXtended InterNET Daemon (xinetd) is an open source super daemon that replaced the original inetd daemon. The xinetd daemon listens for well known services and dispatches the appropriate daemon to properly respond to service requests.\n\nRationale: If there are no xinetd services required, it is recommended that the daemon be disabled."
  impact 1.0
  a = command("systemctl is-enabled xinetd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.1.1_Ensure_time_synchronization_is_in_use" do
  title "Ensure time synchronization is in use"
  desc  "System time should be synchronized between all systems in an environment. This is typically done by establishing an authoritative time server or set of servers and having all systems synchronize their clocks to them.\n\nRationale: Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files have consistent time records across the enterprise, which aids in forensic investigations."
  impact 0.0

  describe 'Compensating Control' do
    skip 'NTP not activate by default.'
  end
  # describe.one do
  #   describe package("ntp") do
  #     it { should be_installed }
  #   end
  #   describe package("chrony") do
  #     it { should be_installed }
  #   end
  # end
end

control "cis benchmark 2.2.1.2_Ensure_ntp_is_configured" do
  title "Ensure ntp is configured"
  desc  "ntp is a daemon which implements the Network Time Protocol (NTP). It is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on NTP can be found at  http://www.ntp.org . ntp can be configured to be a client and/or a server.\n                  \n                  \n                     \n                        \n                     \n                  \n                   This recommendation only applies if ntp is in use on the system.\n\nRationale: If ntp is in use on the system proper configuration is vital to ensuring time synchronization is working properly."
  impact 1.0
  describe.one do
    describe file("/etc/ntp.conf") do
      its("content") { should match(/^\s*restrict\s+(-4\s+)?default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/) }
    end
    describe file("/etc/ntp.conf") do
      its("content") { should match(/^\s*restrict\s+-6\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/) }
    end
    describe file("/etc/ntp.conf") do
      its("content") { should match(/^\s*server\s+\S+/) }
    end
    describe file("/etc/init.d/ntp") do
      its("content") { should match(/^\s*RUNASUSER\s*=\s*ntp\s*(?:#.*)?$/) }
    end
    describe package("ntp") do
      it { should_not be_installed }
    end
  end
end

control "cis benchmark 2.2.1.3_Ensure_chrony_is_configured" do
  title "Ensure chrony is configured"
  desc  "chrony is a daemon which implements the Network Time Protocol (NTP) is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on chrony can be found at http://chrony.tuxfamily.org/\n                      . chrony can be configured to be a client and/or a server.\n\nRationale: If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working properly.\n                    This recommendation only applies if chrony is in use on the system."
  impact 1.0
  describe.one do
    describe file("/etc/chrony/chrony.conf") do
      its("content") { should match(/^\s*server\s+\S+/) }
    end
    processes(/^chronyd/).where { pid > 0 }.entries.each do |entry|
      a = passwd.where { user == "_chrony" }.uids.first
      describe user(entry.user) do
        its("uid") { should cmp a }
      end
    end
    describe package("chrony") do
      it { should_not be_installed }
    end
  end
end

control "cis benchmark 2.2.2_Ensure_X_Window_System_is_not_installed" do
  title "Ensure X Window System is not installed"
  desc  "The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on workstations where users login, but not on servers where users typically do not login.\n\nRationale: Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface."
  impact 1.0
  describe packages(/^xserver-xorg.*/) do
    its("names") { should be_empty }
  end
end

control "cis benchmark 2.2.3_Ensure_Avahi_Server_is_not_enabled" do
  title "Ensure Avahi Server is not enabled"
  desc  "Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine.\n\nRationale: Automatic discovery of network services is not normally required for system functionality. It is recommended to disable the service to reduce the potential attach surface."
  impact 1.0
  a = command("systemctl is-enabled avahi-daemon.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.4_Ensure_CUPS_is_not_enabled" do
  title "Ensure CUPS is not enabled"
  desc  "The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.\n\nRationale: If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be disabled to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled cups.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.5_Ensure_DHCP_Server_is_not_enabled" do
  title "Ensure DHCP Server is not enabled"
  desc  "The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses.\n\nRationale: Unless a system is specifically set up to act as a DHCP server, it is recommended that this service be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled isc-dhcp-server.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
  a = command("systemctl is-enabled isc-dhcp-server6.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.6_Ensure_LDAP_server_is_not_enabled" do
  title "Ensure LDAP server is not enabled"
  desc  "The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.\n\nRationale: If the system will not need to act as an LDAP server, it is recommended that the software be disabled to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled slapd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.7_Ensure_NFS_and_RPC_are_not_enabled" do
  title "Ensure NFS and RPC are not enabled"
  desc  "The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.\n\nRationale: If the system does not export NFS shares or act as an NFS client, it is recommended that these services be disabled to reduce remote attack surface."
  impact 1.0
  a = command("systemctl is-enabled nfs-kernel-server.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
  a = command("systemctl is-enabled rpcbind.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.8_Ensure_DNS_Server_is_not_enabled" do
  title "Ensure DNS Server is not enabled"
  desc  "The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network.\n\nRationale: Unless a system is specifically designated to act as a DNS server, it is recommended that the package be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled bind9.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.9_Ensure_FTP_Server_is_not_enabled" do
  title "Ensure FTP Server is not enabled"
  desc  "The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.\n\nRationale: FTP does not protect the confidentiality of data or authentication credentials. It is recommended sftp be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled vsftpd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.10_Ensure_HTTP_server_is_not_enabled" do
  title "Ensure HTTP server is not enabled"
  desc  "HTTP or web servers provide the ability to host web site content.\n\nRationale: Unless there is a need to run the system as a web server, it is recommended that the package be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled apache2.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.11_Ensure_IMAP_and_POP3_server_is_not_enabled" do
  title "Ensure IMAP and POP3 server is not enabled"
  desc  "dovecot is an open source IMAP and POP3 server for Linux based systems.\n\nRationale: Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the service be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled dovecot.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.12_Ensure_Samba_is_not_enabled" do
  title "Ensure Samba is not enabled"
  desc  "The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Small Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.\n\nRationale: If there is no need to mount directories and file systems to Windows systems, then this service can be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled smbd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.13_Ensure_HTTP_Proxy_Server_is_not_enabled" do
  title "Ensure HTTP Proxy Server is not enabled"
  desc  "Squid is a standard proxy server used in many distributions and environments.\n\nRationale: If there is no need for a proxy server, it is recommended that the squid proxy be deleted to reduce the potential attack surface."
  impact 1.0
  a = command("systemctl is-enabled squid.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.14_Ensure_SNMP_Server_is_not_enabled" do
  title "Ensure SNMP Server is not enabled"
  desc  "The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.\n\nRationale: The SNMP server communicates using SNMP v1, which transmits data in the clear and does not require authentication to execute commands. Unless absolutely necessary, it is recommended that the SNMP service not be used."
  impact 1.0
  a = command("systemctl is-enabled snmpd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.15_Ensure_mail_transfer_agent_is_configured_for_local-only_mode" do
  title "Ensure mail transfer agent is configured for local-only mode"
  desc  "Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail.\n\nRationale: The software for all Mail Transfer Agents is complex and most have a long history of security issues. While it is important to ensure that the system can process local mail messages, it is not necessary to have the MTA's daemon listening on a port unless the server is intended to be a mail server that receives and processes mail from other systems."
  impact 1.0
  describe service('postfix') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
  describe port(25).where { protocol =~ /.*/ && address =~ /^(?!127\.0\.0\.1|::1).*$/ } do
    its("entries") { should be_empty }
  end
end

control "cis benchmark 2.2.16_Ensure_rsync_service_is_not_enabled" do
  title "Ensure rsync service is not enabled"
  desc  "The rsyncd service can be used to synchronize files between systems over network links.\n\nRationale: The rsyncd service presents a security risk as it uses unencrypted protocols for communication."
  impact 1.0
  a = command("systemctl is-enabled rsync.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.2.17_Ensure_NIS_Server_is_not_enabled" do
  title "Ensure NIS Server is not enabled"
  desc  "The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files.\n\nRationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be disabled and other, more secure services be used"
  impact 1.0
  a = command("systemctl is-enabled nis.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 2.3.1_Ensure_NIS_Client_is_not_installed" do
  title "Ensure NIS Client is not installed"
  desc  "The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client (ypbind) was used to bind a machine to an NIS server and receive the distributed configuration files.\n\nRationale: The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed."
  impact 1.0
  describe package("nis") do
    it { should_not be_installed }
  end
end

control "cis benchmark 2.3.2_Ensure_rsh_client_is_not_installed" do
  title "Ensure rsh client is not installed"
  desc  "The rsh package contains the client commands for the rsh services.\n\nRationale: These legacy clients contain numerous security exposures and have been replaced with the more secure SSH package. Even if the server is removed, it is best to ensure the clients are also removed to prevent users from inadvertently attempting to use these commands and therefore exposing their credentials. Note that removing the rsh package removes the clients for rsh, rcp and rlogin."
  impact 1.0
  describe package("rsh-client") do
    it { should_not be_installed }
  end
  describe package("rsh-redone-client") do
    it { should_not be_installed }
  end
end

control "cis benchmark 2.3.3_Ensure_talk_client_is_not_installed" do
  title "Ensure talk client is not installed"
  desc  "The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client, which allows initialization of talk sessions, is installed by default.\n\nRationale: The software presents a security risk as it uses unencrypted protocols for communication."
  impact 1.0
  describe package("talk") do
    it { should_not be_installed }
  end
end

control "cis benchmark 2.3.4_Ensure_telnet_client_is_not_installed" do
  title "Ensure telnet client is not installed"
  desc  "The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol.\n\nRationale: The telnet protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The ssh package provides an encrypted session and stronger security and is included in most Linux distributions."
  impact 1.0
  describe package("telnet") do
    it { should_not be_installed }
  end
end

control "cis benchmark 2.3.5_Ensure_LDAP_client_is_not_installed" do
  title "Ensure LDAP client is not installed"
  desc  "The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.\n\nRationale: If the system will not need to act as an LDAP client, it is recommended that the software be removed to reduce the potential attack surface."
  impact 1.0
  describe package("ldap-utils") do
    it { should_not be_installed }
  end
end

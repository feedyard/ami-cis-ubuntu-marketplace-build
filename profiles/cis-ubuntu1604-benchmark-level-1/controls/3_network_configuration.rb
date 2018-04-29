# Controls mapped to CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0 12-28-2017

control "cis benchmark 3.1.1_Ensure_IP_forwarding_is_disabled" do
  title "Ensure IP forwarding is disabled"
  desc  "The net.ipv4.ip_forward flag is used to tell the system whether it can forward packets or not.\n\nRationale: Setting the flag to 0 ensures that a system with multiple interfaces (for example, a hard proxy), will never be able to forward packets, and therefore, never serve as a router."
  impact 1.0
  describe kernel_parameter("net.ipv4.ip_forward") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.ip_forward") do
    its("value") { should eq 0 }
  end
end

control "cis benchmark 3.1.2_Ensure_packet_redirect_sending_is_disabled" do
  title "Ensure packet redirect sending is disabled"
  desc  "ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as a router (in a host only configuration), there is no need to send redirects.\n\nRationale: An attacker could use a compromised host to send invalid ICMP redirects to other router devices in an attempt to corrupt routing and have users access a system set up by the attacker as opposed to a valid system."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.send_redirects") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.send_redirects") do
    its("value") { should eq 0 }
  end
end

control "cis benchmark 3.2.1_Ensure_source_routed_packets_are_not_accepted" do
  title "Ensure source routed packets are not accepted"
  desc  "In networking, source routing allows a sender to partially or fully specify the route packets take through a network. In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used.\n\nRationale: Setting net.ipv4.conf.all.accept_source_route and net.ipv4.conf.default.accept_source_route to 0 disables the system from accepting source routed packets. Assume this system was capable of routing packets to Internet routable addresses on one interface and private addresses on another interface. Assume that the private addresses were not routable to the Internet routable addresses and vice versa. Under normal routing circumstances, an attacker from the Internet routable addresses could not use the system as a way to reach the private address systems. If, however, source routed packets were allowed, they could be used to gain access to the private address systems as the route could be specified, rather than rely on routing protocols that did not allow this routing."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_source_route") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.accept_source_route") do
    its("value") { should eq 0 }
  end
end

control "cis benchmark 3.2.2_Ensure_ICMP_redirects_are_not_accepted" do
  title "Ensure ICMP redirects are not accepted"
  desc  "ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects to 0, the system will not accept any ICMP redirect messages, and therefore, won't allow outsiders to update the system's routing tables.\n\nRationale: Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables and get them to send packets to incorrect networks and allow your system packets to be captured."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.accept_redirects") do
    its("value") { should eq 0 }
  end
end

control "cis benchmark 3.2.3_Ensure_secure_ICMP_redirects_are_not_accepted" do
  title "Ensure secure ICMP redirects are not accepted"
  desc  "Secure ICMP redirects are the same as ICMP redirects, except they come from gateways listed on the default gateway list. It is assumed that these gateways are known to your system, and that they are likely to be secure.\n\nRationale: It is still possible for even known gateways to be compromised. Setting net.ipv4.conf.all.secure_redirects to 0 protects the system from routing table updates by possibly compromised known gateways."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.secure_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.secure_redirects") do
    its("value") { should eq 0 }
  end
  describe kernel_parameter("net.ipv4.conf.default.secure_redirects") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.secure_redirects") do
    its("value") { should eq 0 }
  end
end

control "cis benchmark 3.2.4_Ensure_suspicious_packets_are_logged" do
  title "Ensure suspicious packets are logged"
  desc  "When enabled, this feature logs packets with un-routable source addresses to the kernel log.\n\nRationale: Enabling this feature and logging these packets allows an administrator to investigate the possibility that an attacker is sending spoofed packets to their system."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.log_martians") do
    its("value") { should eq 1 }
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.log_martians") do
    its("value") { should eq 1 }
  end
end

control "cis benchmark 3.2.5_Ensure_broadcast_ICMP_requests_are_ignored" do
  title "Ensure broadcast ICMP requests are ignored"
  desc  "Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo and timestamp requests to broadcast and multicast addresses.\n\nRationale: Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for your network could be used to trick your host into starting (or participating) in a Smurf attack. A Smurf attack relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed source address. All hosts receiving this message and responding would send echo-reply messages back to the spoofed address, which is probably not routable. If many hosts respond to the packets, the amount of traffic on the network could be significantly multiplied."
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts") do
    its("value") { should eq 1 }
  end
end

control "cis benchmark 3.2.6_Ensure_bogus_ICMP_responses_are_ignored" do
  title "Ensure bogus ICMP responses are ignored"
  desc  "Setting icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from filling up with useless log messages.\n\nRationale: Some routers (and some attackers) will send responses that violate RFC-1122 and attempt to fill up a log file system with many useless error messages."
  impact 1.0
  describe kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses") do
    its("value") { should eq 1 }
  end
end

control "cis benchmark 3.2.7_Ensure_Reverse_Path_Filtering_is_enabled" do
  title "Ensure Reverse Path Filtering is enabled"
  desc  "Setting net.ipv4.conf.all.rp_filter and net.ipv4.conf.default.rp_filter to 1 forces the Linux kernel to utilize reverse path filtering on a received packet to determine if the packet was valid. Essentially, with reverse path filtering, if the return packet does not go out the same interface that the corresponding source packet came from, the packet is dropped (and logged if log_martians is set).\n\nRationale: Setting these flags is a good way to deter attackers from sending your system bogus packets that cannot be responded to. One instance where this feature breaks down is if asymmetrical routing is employed. This would occur when using dynamic routing protocols (bgp, ospf, etc) on your system. If you are using asymmetrical routing on your system, you will not be able to enable this feature without breaking the routing."
  impact 1.0
  describe kernel_parameter("net.ipv4.conf.all.rp_filter") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.all.rp_filter") do
    its("value") { should eq 1 }
  end
  describe kernel_parameter("net.ipv4.conf.default.rp_filter") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.conf.default.rp_filter") do
    its("value") { should eq 1 }
  end
end

control "cis benchmark 3.2.8_Ensure_TCP_SYN_Cookies_is_enabled" do
  title "Ensure TCP SYN Cookies is enabled"
  desc  "When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that encodes the source and destination IP address and port number and the time the packet was sent. A legitimate connection would send the ACK packet of the three way handshake with the specially crafted sequence number. This allows the system to verify that it has received a valid response to a SYN cookie and allow the connection, even though there is no corresponding SYN in the queue.\n\nRationale: Attackers use SYN flood attacks to perform a denial of service attacked on a system by sending many SYN packets without completing the three way handshake. This will quickly use up slots in the kernel's half-open connection queue and prevent legitimate connections from succeeding. SYN cookies allow the system to keep accepting valid connections, even if under a denial of service attack."
  impact 1.0
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("net.ipv4.tcp_syncookies") do
    its("value") { should eq 1 }
  end
end

control "cis benchmark 3.3.1_Ensure_IPv6_router_advertisements_are_not_accepted" do
  title "Ensure IPv6 router advertisements are not accepted"
  desc  "This setting disables the system's ability to accept IPv6 router advertisements.\n\nRationale: It is recommended that systems not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes."
  impact 0.0
  describe.one do
    describe kernel_parameter("net.ipv6.conf.all.accept_ra") do
      its("value") { should_not be_nil }
    end
    describe kernel_parameter("net.ipv6.conf.all.accept_ra") do
      its("value") { should eq 0 }
    end
    describe kernel_parameter("net.ipv6.conf.default.accept_ra") do
      its("value") { should_not be_nil }
    end
    describe kernel_parameter("net.ipv6.conf.default.accept_ra") do
      its("value") { should eq 0 }
    end
    describe file("/boot/grub/grub.cfg") do
      its("content") { should match(/^\s*kernel\S+(\s+\S+)+\s+ipv6\.disable=1^\s*linux\S*(\s+\S+)+\s+ipv6\.disable=1/) }
    end
  end
end

control "cis benchmark 3.3.2_Ensure_IPv6_redirects_are_not_accepted" do
  title "Ensure IPv6 redirects are not accepted"
  desc  "This setting prevents the system from accepting ICMP redirects. ICMP redirects tell the system about alternate routes for sending traffic.\n\nRationale: It is recommended that systems not accept ICMP redirects as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes."
  impact 0.0
  describe.one do
    describe kernel_parameter("net.ipv6.conf.all.accept_redirects") do
      its("value") { should_not be_nil }
    end
    describe kernel_parameter("net.ipv6.conf.all.accept_redirects") do
      its("value") { should eq 0 }
    end
    describe kernel_parameter("net.ipv6.conf.default.accept_redirects") do
      its("value") { should_not be_nil }
    end
    describe kernel_parameter("net.ipv6.conf.default.accept_redirects") do
      its("value") { should eq 0 }
    end
    describe file("/boot/grub/grub.cfg") do
      its("content") { should match(/^\s*linux\S*(\s+\S+)+\s+ipv6\.disable=1/) }
    end
  end
end

control "cis benchmark 3.3.3_Ensure_IPv6_is_disabled" do
  title "Ensure IPv6 is disabled"
  desc  "Although IPv6 has many advantages over IPv4, few organizations have implemented IPv6.\n\nRationale: If IPv6 is not to be used, it is recommended that it be disabled to reduce the attack surface of the system."
  impact 0.0

  describe 'Compensating Control' do
    skip 'CIS AWS Marketplace ami - ipv6 disabled by default'
  end
  # describe file("/boot/grub/grub.cfg") do
  #   its("content") { should match(/^\s*linux\S*(\s+\S+)+\s+ipv6\.disable=1/) }
  # end
end

control "cis benchmark 3.4.1_Ensure_TCP_Wrappers_is_installed" do
  title "Ensure TCP Wrappers is installed"
  desc  "TCP Wrappers provides a simple access list and standardized logging method for services capable of supporting it. In the past, services that were called from inetd and xinetd supported the use of tcp wrappers. As inetd and xinetd have been falling in disuse, any service that can support tcp wrappers will have the libwrap.so library attached to it.\n\nRationale: TCP Wrappers provide a good simple access list mechanism to services that may not have that support built in. It is recommended that all services that can support TCP Wrappers, use it."
  impact 1.0
  describe package("tcpd") do
    it { should be_installed }
  end
end

control "cis benchmark 3.4.2_Ensure_etchosts.allow_is_configured" do
  title "Ensure /etc/hosts.allow is configured"
  desc  "The /etc/hosts.allow file specifies which IP addresses are permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.deny file.\n\nRationale: The /etc/hosts.allow file supports access control by IP and helps ensure that only authorized systems can connect to the system."
  impact 1.0
  describe file("/etc/hosts.allow") do
    it { should exist }
  end
end


control "cis benchmark 3.4.3_Ensure_etchosts.deny_is_configured" do
  title "Ensure /etc/hosts.deny is configured"
  desc  "The /etc/hosts.deny file specifies which IP addresses are not permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.allow file.\n\nRationale: The /etc/hosts.deny file serves as a failsafe so that any host not specified in /etc/hosts.allow is denied access to the system."
  impact 1.0

  describe 'Compensating Control' do
    skip 'Compensating Control: Nodes used in kubernetes cluster on AWS. Existing security groups and routing rules restrict access to a limited number of known host locations'
  end
  # describe file("/etc/hosts.deny") do
  #   its("content") { should match(/^ALL: ALL/) }
  # end
end

control "cis benchmark 3.4.4_Ensure_permissions_on_etchosts.allow_are_configured" do
  title "Ensure permissions on /etc/hosts.allow are configured"
  desc  "The /etc/hosts.allow file contains networking information that is used by many applications and therefore must be readable for these applications to operate.\n\nRationale: It is critical to ensure that the /etc/hosts.allow file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/hosts.allow") do
    it { should exist }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/hosts.allow") do
    its("sgid") { should equal false }
  end
  describe file("/etc/hosts.allow") do
    its("sticky") { should equal false }
  end
  describe file("/etc/hosts.allow") do
    its("suid") { should equal false }
  end
  describe file("/etc/hosts.allow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/hosts.allow") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/hosts.allow") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/hosts.allow") do
    it { should be_writable.by "owner" }
  end
end

control "cis benchmark 3.4.5_Ensure_permissions_on_etchosts.deny_are_644" do
  title "Ensure permissions on /etc/hosts.deny are 644"
  desc  "The /etc/hosts.deny file contains network information that is used by many system applications and therefore must be readable for these applications to operate.\n\nRationale: It is critical to ensure that the /etc/hosts.deny file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/hosts.deny") do
    it { should exist }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/hosts.deny") do
    its("sgid") { should equal false }
  end
  describe file("/etc/hosts.deny") do
    its("sticky") { should equal false }
  end
  describe file("/etc/hosts.deny") do
    its("suid") { should equal false }
  end
  describe file("/etc/hosts.deny") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/hosts.deny") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/hosts.deny") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/hosts.deny") do
    it { should be_writable.by "owner" }
  end
end

control "cis benchmark 3.5.1_Ensure_DCCP_is_disabled" do
  title "Ensure DCCP is disabled"
  desc  "The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports streaming media and telephony. DCCP provides a way to gain access to congestion control, without having to do it at the application layer, but does not provide in-sequence delivery.\n\nRationale: If the protocol is not required, it is recommended that the drivers not be installed to reduce the potential attack surface."
  impact 0.0
  a = command("modprobe -n -v dccp").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^dccp\s+/) }
    end
  end
end

control "cis benchmark 3.5.2_Ensure_SCTP_is_disabled" do
  title "Ensure SCTP is disabled"
  desc  "The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support message oriented communication, with several streams of messages in one connection. It serves a similar function as TCP and UDP, incorporating features of both. It is message-oriented like UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP.\n\nRationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
  impact 0.0
  a = command("modprobe -n -v sctp").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^sctp\s+/) }
    end
  end
end

control "cis benchmark 3.5.3_Ensure_RDS_is_disabled" do
  title "Ensure RDS is disabled"
  desc  "The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide low-latency, high-bandwidth communications between cluster nodes. It was developed by the Oracle Corporation.\n\nRationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
  impact 0.0
  a = command("modprobe -n -v rds").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^rds\s+/) }
    end
  end
end

control "cis benchmark 3.5.4_Ensure_TIPC_is_disabled" do
  title "Ensure TIPC is disabled"
  desc  "The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communication between cluster nodes.\n\nRationale: If the protocol is not being used, it is recommended that kernel module not be loaded, disabling the service to reduce the potential attack surface."
  impact 0.0
  a = command("modprobe -n -v tipc").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^install\s+\/bin\/true\s*$/) }
      end
    end
  end
  a = command("lsmod").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/^tipc\s+/) }
    end
  end
end

control "cis benchmark 3.6.1_Ensure_iptables_is_installed" do
  title "Ensure iptables is installed"
  desc  "iptables allows configuration of the IPv4 tables in the linux kernel and the rules stored within them. Most firewall configuration utilities operate as a front end to iptables.\n\nRationale: iptables is required for firewall management and configuration."
  impact 1.0
  describe package("iptables") do
    it { should be_installed }
  end
end



control "cis benchmark 3.6.2_Ensure_default_deny_firewall_policy" do
  title "Ensure default deny firewall policy"
  desc  "A default deny all policy on connections ensures that any unconfigured network usage will be rejected.\n\nRationale: With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier to white list acceptable usage than to black list unacceptable usage."
  impact 1.0

  describe 'Compensating Control' do
    skip 'Compensating Control: IPtable definitions defined to support kubernetes dynamic architecture'
  end
  # a = command("iptables -L").stdout.scan(/.+/)
  # describe a do
  #   its("length") { should be > 0 }
  # end
  # describe.one do
  #   a.each do |entry|
  #     describe entry do
  #       it { should match(/^Chain INPUT \(policy (DROP|REJECT)\)$/) }
  #     end
  #   end
  # end
  # a = command("iptables -L").stdout.scan(/.+/)
  # describe a do
  #   its("length") { should be > 0 }
  # end
  # describe.one do
  #   a.each do |entry|
  #     describe entry do
  #       it { should match(/^Chain FORWARD \(policy (DROP|REJECT)\)$/) }
  #     end
  #   end
  # end
  # a = command("iptables -L").stdout.scan(/.+/)
  # describe a do
  #   its("length") { should be > 0 }
  # end
  # describe.one do
  #   a.each do |entry|
  #     describe entry do
  #       it { should match(/^Chain OUTPUT \(policy (DROP|REJECT)\)$/) }
  #     end
  #   end
  # end
end

control "cis benchmark 3.6.3_Ensure_loopback_traffic_is_configured" do
  title "Ensure loopback traffic is configured"
  desc  "Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network (127.0.0.0/8).\n\nRationale: Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network (127.0.0.0/8) traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure."
  impact 1.0
  a = command("iptables -L INPUT -v -n").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^\s*\S+\s+\S+\s+ACCEPT\s+all\s+--\s+lo\s+\*\s+0\.0\.0\.0\/0\s+0\.0\.0\.0\/0\s*$/) }
      end
    end
  end
  a = command("iptables -L INPUT -v -n").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^\s*\S+\s+\S+\s+DROP\s+all\s+--\s+\*\s+\*\s+127\.0\.0\.0\/8\s+0\.0\.0\.0\/0\s*$/) }
      end
    end
  end
  a = command("iptables -L OUTPUT -v -n").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/^\s*\S+\s+\S+\s+ACCEPT\s+all\s+--\s+\*\s+lo\s+0\.0\.0\.0\/0\s+0\.0\.0\.0\/0\s*$/) }
      end
    end
  end
end

control "cis benchmark 3.6.4_Ensure_outbound_and_established_connections_are_configured" do
  title "Ensure outbound and established connections are configured"
  desc  "Configure the firewall rules for new outbound, and established connections.\n\nRationale: If rules are not in place for new outbound, and established connections all packets will be dropped by the default policy preventing network usage."
  impact 0.0

  describe 'Compensating Control' do
    skip 'Compensating Control: NAT gateway for all outbound connections. Proposed Whitelist Proxy in backlog'
  end
end

control "cis benchmark 3.6.5_Ensure_firewall_rules_exist_for_all_open_ports" do
  title "Ensure firewall rules exist for all open ports"
  desc  "Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.\n\nRationale: Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports."
  impact 1.0

  describe 'Compensating Control' do
    skip 'Compensating Control: Kops managed AWS security group define Kubernetes required port access'
  end
  # describe "SCAP oval resource shellcommand_test could not be loaded: shellcommand_test can only test with a line_selection content at the moment" do
  #   skip "SCAP oval resource shellcommand_test could not be loaded: shellcommand_test can only test with a line_selection content at the moment"
  # end
  # describe "SCAP oval resource shellcommand_test could not be loaded: SCAP::OVAL::ShellCommandTest cannot find node reference: state#state_ref" do
  #   skip "SCAP oval resource shellcommand_test could not be loaded: SCAP::OVAL::ShellCommandTest cannot find node reference: state#state_ref"
  # end
end

control "cis benchmark 3.7_Ensure_wireless_interfaces_are_disabled" do
  title "Ensure wireless interfaces are disabled"
  desc  "Wireless networking is used when wired networks are unavailable. Ubuntu contains a wireless tool kit to allow system administrators to configure and use wireless networks.\n\nRationale: If wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface."
  impact 0.0

  describe 'Compensating Control' do
    skip 'Compensating Control: No wireless option on AWS instances'
  end
end

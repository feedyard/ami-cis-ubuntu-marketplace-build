# Controls mapped to CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0 12-28-2017

control "cis benchmark 5.1.1_Ensure_cron_daemon_is_enabled" do
  title "Ensure cron daemon is enabled"
  desc  "The cron daemon is used to execute batch jobs on the system.\n\nRationale: While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run, and cron is used to execute them."
  impact 1.0
  a = command("systemctl is-enabled cron.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should match(/.+/) }
    end
  end
end

control "cis benchmark 5.1.2_Ensure_permissions_on_etccrontab_are_configured" do
  title "Ensure permissions on /etc/crontab are configured"
  desc  "The /etc/crontab file is used by cron to control its own jobs. The commands in this item make sure that root is the user and group owner of the file and that only the owner can access the file.\n\nRationale: This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access to these files could provide users with the ability to gain insight on system jobs that run on the system and could provide them a way to gain unauthorized privileged access."
  impact 1.0
  describe file("/etc/crontab") do
    it { should exist }
  end
  describe file("/etc/crontab") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/crontab") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/crontab") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/crontab") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/crontab") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/crontab") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 5.1.3_Ensure_permissions_on_etccron.hourly_are_configured" do
  title "Ensure permissions on /etc/cron.hourly are configured"
  desc  "This directory contains system cron jobs that need to run on an hourly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.hourly") do
    it { should exist }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.hourly") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 5.1.4_Ensure_permissions_on_etccron.daily_are_configured" do
  title "Ensure permissions on /etc/cron.daily are configured"
  desc  "The /etc/cron.daily directory contains system cron jobs that need to run on a daily basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.daily") do
    it { should exist }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.daily") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.daily") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.daily") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 5.1.5_Ensure_permissions_on_etccron.weekly_are_configured" do
  title "Ensure permissions on /etc/cron.weekly are configured"
  desc  "The /etc/cron.weekly directory contains system cron jobs that need to run on a weekly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.weekly") do
    it { should exist }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.weekly") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 5.1.6_Ensure_permissions_on_etccron.monthly_are_configured" do
  title "Ensure permissions on /etc/cron.monthly are configured"
  desc  "The /etc/cron.monthly directory contains system cron jobs that need to run on a monthly basis. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.monthly") do
    it { should exist }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.monthly") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 5.1.7_Ensure_permissions_on_etccron.d_are_configured" do
  title "Ensure permissions on /etc/cron.d are configured"
  desc  "The /etc/cron.d directory contains system cron jobs that need to run in a similar manner to the hourly, daily weekly and monthly jobs from /etc/crontab, but require more granular control as to when they run. The files in this directory cannot be manipulated by the crontab command, but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.\n\nRationale: Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls."
  impact 1.0
  describe file("/etc/cron.d") do
    it { should exist }
  end
  describe file("/etc/cron.d") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.d") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.d") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.d") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.d") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 5.1.8_Ensure_atcron_is_restricted_to_authorized_users" do
  title "Ensure at/cron is restricted to authorized users"
  desc  "Configure /etc/cron.allow and /etc/at.allow to allow specific users to use these services. If /etc/cron.allow or /etc/at.allow do not exist, then /etc/at.deny and /etc/cron.deny are checked. Any user not specifically defined in those files is allowed to use at and cron. By removing the files, only users in /etc/cron.allow and /etc/at.allow are allowed to use at and cron. Note that even though a given user is not listed in cron.allow, cron jobs can still be run as that user. The cron.allow file only controls administrative access to the crontab command for scheduling and modifying cron jobs.\n\nRationale: On many systems, only the system administrator is authorized to schedule cron jobs. Using the cron.allow file to control who can run cron jobs enforces this policy. It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user ID to the system and forget to add it to the deny files."
  impact 1.0
  describe file("/etc/cron.deny") do
    it { should_not exist }
  end
  describe file("/etc/at.deny") do
    it { should_not exist }
  end
  describe file("/etc/cron.allow") do
    it { should exist }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/cron.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/cron.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/cron.allow") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/at.allow") do
    it { should exist }
  end
  describe file("/etc/at.allow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/at.allow") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/at.allow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/at.allow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/at.allow") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 5.2.1_Ensure_permissions_on_etcsshsshd_config_are_configured" do
  title "Ensure permissions on /etc/ssh/sshd_config are configured"
  desc  "The /etc/ssh/sshd_config file contains configuration specifications for sshd. The command below sets the owner and group of the file to root.\n\nRationale: The /etc/ssh/sshd_config file needs to be protected from unauthorized changes by non-privileged users."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    it { should exist }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/ssh/sshd_config") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 5.2.2_Ensure_SSH_Protocol_is_set_to_2" do
  title "Ensure SSH Protocol is set to 2"
  desc  "SSH supports two different and incompatible protocols: SSH1 and SSH2. SSH1 was the original protocol and was subject to security issues. SSH2 is more advanced and secure.\n\nRationale: SSH v1 suffers from insecurities that do not affect SSH v2."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*Protocol\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*Protocol\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "2" }
    end
  end
end

control "cis benchmark 5.2.3_Ensure_SSH_LogLevel_is_set_to_INFO" do
  title "Ensure SSH LogLevel is set to INFO"
  desc  "The INFO parameter specifies that login and logout activity will be logged.\n\nRationale: SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically not recommended other than strictly for debugging SSH communications since it provides so much data that it is difficult to identify important security information. INFO level is the basic level that only records login activity of SSH users. In many situations, such as Incident Response, it is important to determine when a particular user was active on a system. The logout record can eliminate those users who disconnected, which helps narrow the field."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*LogLevel\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*LogLevel\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "INFO" }
    end
  end
end

control "cis benchmark 5.2.4_Ensure_SSH_X11_forwarding_is_disabled" do
  title "Ensure SSH X11 forwarding is disabled"
  desc  "The X11Forwarding parameter provides the ability to tunnel X11 traffic through the connection to enable remote graphic connections.\n\nRationale: Disable X11 forwarding unless there is an operational requirement to use X11 applications directly. There is a small risk that the remote X11 servers of users who are logged in via SSH with X11 forwarding could be compromised by other users on the X11 server. Note that even if X11 forwarding is disabled, users can always install their own forwarders."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*X11Forwarding\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*X11Forwarding\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "cis benchmark 5.2.5_Ensure_SSH_MaxAuthTries_is_set_to_4_or_less" do
  title "Ensure SSH MaxAuthTries is set to 4 or less"
  desc  "The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. When the login failure count reaches half the number, error messages will be written to the syslog file detailing the login failure.\n\nRationale: Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. While the recommended setting is 4, set the number based on site policy."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*MaxAuthTries\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*MaxAuthTries\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 4 }
    end
  end
end

control "cis benchmark 5.2.6_Ensure_SSH_IgnoreRhosts_is_enabled" do
  title "Ensure SSH IgnoreRhosts is enabled"
  desc  "The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication.\n\nRationale: Setting this parameter forces users to enter a password when authenticating with ssh."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*IgnoreRhosts\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*IgnoreRhosts\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "yes" }
    end
  end
end

control "cis benchmark 5.2.7_Ensure_SSH_HostbasedAuthentication_is_disabled" do
  title "Ensure SSH HostbasedAuthentication is disabled"
  desc  "The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user of .rhosts, or /etc/hosts.equiv, along with successful public key client host authentication. This option only applies to SSH Protocol Version 2.\n\nRationale: Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf, disabling the ability to use .rhosts files in SSH provides an additional layer of protection ."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*HostbasedAuthentication\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*HostbasedAuthentication\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "cis benchmark 5.2.8_Ensure_SSH_root_login_is_disabled" do
  title "Ensure SSH root login is disabled"
  desc  "The PermitRootLogin parameter specifies if the root user can log in using ssh(1). The default is no.\n\nRationale: Disallowing root logins over SSH requires system admins to authenticate using their own individual account, then escalating to root via sudo or su. This in turn limits opportunity for non-repudiation and provides a clear audit trail in the event of a security incident"
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PermitRootLogin\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitRootLogin\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "cis benchmark 5.2.9_Ensure_SSH_PermitEmptyPasswords_is_disabled" do
  title "Ensure SSH PermitEmptyPasswords is disabled"
  desc  "The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts with empty password strings.\n\nRationale: Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system"
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PermitEmptyPasswords\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitEmptyPasswords\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "cis benchmark 5.2.10_Ensure_SSH_PermitUserEnvironment_is_disabled" do
  title "Ensure SSH PermitUserEnvironment is disabled"
  desc  "The PermitUserEnvironment option allows users to present environment options to the ssh daemon.\n\nRationale: Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has ssh executing trojan'd programs)"
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*PermitUserEnvironment\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*PermitUserEnvironment\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should eq "no" }
    end
  end
end

control "cis benchmark 5.2.11_Ensure_only_approved_MAC_algorithms_are_used" do
  title "Ensure only approved MAC algorithms are used"
  desc  "This variable limits the types of MAC algorithms that SSH can use during communication.\n\nRationale: MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase exploitability in SSH downgrade attacks. Weak algorithms continue to have a great deal of attention as a weak spot that can be exploited with expanded computing power. An attacker that breaks the algorithm could take advantage of a MiTM position to decrypt the SSH tunnel and capture credentials and information"
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*MACs\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*MACs\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp(/^((hmac-sha2-512-etm@openssh\.com|hmac-sha2-256-etm@openssh\.com|umac-128-etm@openssh\.com|hmac-sha2-512|hmac-sha2-256|umac-128@openssh\.com|curve25519-sha256@libssh\.org|diffie-hellman-group-exchange-sha256),)*(hmac-sha2-512-etm@openssh\.com|hmac-sha2-256-etm@openssh\.com|umac-128-etm@openssh\.com|hmac-sha2-512|hmac-sha2-256|umac-128@openssh\.com)$/) }
    end
  end
end

control "cis benchmark 5.2.12_Ensure_SSH_Idle_Timeout_Interval_is_configured" do
  title "Ensure SSH Idle Timeout Interval is configured"
  desc  "The two options ClientAliveInterval and ClientAliveCountMax control the timeout of ssh sessions. When the ClientAliveInterval variable is set, ssh sessions that have no activity for the specified length of time are terminated. When the ClientAliveCountMax variable is set, sshd will send client alive messages at every ClientAliveInterval interval. When the number of consecutive client alive messages are sent with no response from the client, the ssh session is terminated. For example, if the ClientAliveInterval is set to 15 seconds and the ClientAliveCountMax is set to 3, the client ssh session will be terminated after 45 seconds of idle time.\n\nRationale: Having no timeout value associated with a connection could allow an unauthorized user access to another user's ssh session (e.g. user walks away from their computer and doesn't lock the screen). Setting a timeout value at least reduces the risk of this happening.. While the recommended setting is 300 seconds (5 minutes), set this timeout value based on site policy. The recommended setting for ClientAliveCountMax is 0. In this case, the client session will be terminated after 5 minutes of idle time and no keepalive messages will be sent."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*ClientAliveInterval\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveInterval\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 300 }
    end
  end
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*ClientAliveCountMax\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*ClientAliveCountMax\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 3 }
    end
  end
end

control "cis benchmark 5.2.13_Ensure_SSH_LoginGraceTime_is_set_to_one_minute_or_less" do
  title "Ensure SSH LoginGraceTime is set to one minute or less"
  desc  "The LoginGraceTime parameter specifies the time allowed for successful authentication to the SSH server. The longer the Grace period is the more open unauthenticated connections can exist. Like other session controls in this session the Grace Period should be limited to appropriate organizational limits to ensure the service is available for needed access.\n\nRationale: Setting the LoginGraceTime parameter to a low number will minimize the risk of successful brute force attacks to the SSH server. It will also limit the number of concurrent unauthenticated connections While the recommended setting is 60 seconds (1 Minute), set the number based on site policy."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*LoginGraceTime\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*LoginGraceTime\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp <= 60 }
    end
  end
end


control "cis benchmark 5.2.14_Ensure_SSH_access_is_limited" do
  title "Ensure SSH access is limited"
  desc  "There are several options available to limit which users and group can access the system via SSH. It is recommended that at least one of the following options be leveraged:\n               \n                   AllowUsers\n                  \n                The AllowUsers variable gives the system administrator the option of allowing specific users to ssh into the system. The list consists of comma separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by only allowing the allowed users to log in from a particular host, the entry can be specified in the form of user@host.\n               \n                   AllowGroups\n                  \n                The AllowGroups variable gives the system administrator the option of allowing specific groups of users to ssh into the system. The list consists of comma separated group names. Numeric group IDs are not recognized with this variable.\n               \n                   DenyUsers\n                  \n                The DenyUsers variable gives the system administrator the option of denying specific users to ssh into the system. The list consists of comma separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by specifically denying a user's access from a particular host, the entry can be specified in the form of user@host.\n               \n                   DenyGroups\n                  \n                The DenyGroups variable gives the system administrator the option of denying specific groups of users to ssh into the system. The list consists of comma separated group names. Numeric group IDs are not recognized with this variable.\n\nRationale: Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system."
  impact 1.0

  describe 'Compensating Controls' do
    skip 'Compensating Control: AWS instance roles, application security groups, private network, private certificate used to control access'
  end
  # describe file("/etc/ssh/sshd_config") do
  #   its("content") { should match(/^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\s+(\S+)/) }
  # end
end

control "cis benchmark 5.2.15_Ensure_SSH_warning_banner_is_configured" do
  title "Ensure SSH warning banner is configured"
  desc  "The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. By default, no banner is displayed.\n\nRationale: Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning message prior to the normal user login may assist the prosecution of trespassers on the computer system."
  impact 1.0
  describe file("/etc/ssh/sshd_config") do
    its("content") { should match(/^\s*Banner\s+(\S+)\s*(?:#.*)?$/) }
  end
  file("/etc/ssh/sshd_config").content.to_s.scan(/^\s*Banner\s+(\S+)\s*(?:#.*)?$/).flatten.each do |entry|
    describe entry do
      it { should cmp(/.+/) }
    end
  end
end

control "cis benchmark 5.3.1_Ensure_password_creation_requirements_are_configured" do
  title "Ensure password creation requirements are configured"
  desc  "The pam_pwquality.so module checks the strength of passwords. It performs checks such as making sure a password is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. The following are definitions of the  pam_pwquality.so options.\n               \n                  \n                      try_first_pass - retrieve the password from a previous stacked PAM module. If not available, then prompt the user for a password.\n                        \n                           \n                        \n                     \n                  \n                  \n                      retry=3 - Allow 3 tries before sending back a failure.\n                The following options are set in the /etc/security/pwquality.conf file:\n               \n                   minlen=14 - password must be 14 characters or more\n                   dcredit=-1 - provide at least one digit\n                   ucredit=-1 - provide at least one uppercase character\n                   ocredit=-1 - provide at least one special character\n                   lcredit=-1 - provide at least one lowercase character\n               \n                 The settings shown above are one possible policy. Alter these values to conform to your own organization's password policies.\n\nRationale: Strong passwords protect systems from being hacked through brute force methods."
  impact 1.0
  describe file("/etc/pam.d/common-password") do
    its("content") { should match(/^\s*password\s+requisite\s+pam_pwquality\.so\s+(\S+\s+)*try_first_pass/) }
  end
  describe file("/etc/pam.d/common-password") do
    its("content") { should match(/^\s*password\s+requisite\s+pam_pwquality\.so\s+(\S+\s+)*retry=[3210]/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*minlen\s*=\s*(1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\s*(\s+#.*)?$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*dcredit\s*=\s*-[1-9][0-9]*\s*(\s+#.*)?$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*lcredit\s*=\s*-[1-9][0-9]*\s*(\s+#.*)?$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*ucredit\s*=\s*-[1-9][0-9]*\s*(\s+#.*)?$/) }
  end
  describe file("/etc/security/pwquality.conf") do
    its("content") { should match(/^\s*ocredit\s*=\s*-[1-9][0-9]*\s*(\s+#.*)?$/) }
  end
end

control "cis benchmark 5.3.2_Ensure_lockout_for_failed_password_attempts_is_configured" do
  title "Ensure lockout for failed password attempts is configured"
  desc  "Lock out users after n unsuccessful consecutive login attempts. The first sets of changes are made to the PAM configuration files. The second set of changes are applied to the program specific PAM configuration file. The second set of changes must be applied to each program that will lock out users. Check the documentation for each secondary program for instructions on how to configure them to work with PAM. Set the lockout number to the policy in effect at your site.\n\nRationale: Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems."
  impact 0.0

  describe 'Compensating Controls' do
    skip 'Compensating Controls: password access managed by AWS IAM'
  end
end

control "cis benchmark 5.3.3_Ensure_password_reuse_is_limited" do
  title "Ensure password reuse is limited"
  desc  "The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords.\n\nRationale: Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password. Note that these change only apply to accounts configured on the local system."
  impact 1.0
  describe file("/etc/pam.d/common-password") do
    its("content") { should match(/^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*remember=([56789]|[1-9][0-9]+)/) }
  end
end

control "cis benchmark 5.3.4_Ensure_password_hashing_algorithm_is_SHA-512" do
  title "Ensure password hashing algorithm is SHA-512"
  desc  "The commands below change password encryption from md5 to sha512 (a much stronger hashing algorithm). All existing accounts will need to perform a password change to upgrade the stored hashes to the new algorithm.\n\nRationale: The SHA-512 algorithm provides much stronger hashing than MD5, thus providing additional protection to the system by increasing the level of effort for an attacker to successfully determine passwords. Note that these change only apply to accounts configured on the local system."
  impact 1.0
  describe file("/etc/pam.d/common-password") do
    its("content") { should match(/^password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512/) }
  end
end

control "cis benchmark 5.4.1.1_Ensure_password_expiration_is_90_days_or_less" do
  title "Ensure password expiration is 90 days or less"
  desc  "The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire once they reach a defined age. It is recommended that the PASS_MAX_DAYS parameter be set to less than or equal to 90 days.\n\nRationale: The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity."
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MAX_DAYS\s+(90|[1-8][0-9]|[1-9])\s*(\s+#.*)?$/) }
  end
  shadow.user(/.+/).entries.each do |entry|
    describe.one do
      describe entry do
        its("password") { should_not cmp(/^[^!*]/) }
      end
      describe entry do
        its("max_days") { should_not cmp > 90 }
      end
    end
  end
end

control "cis benchmark 5.4.1.2_Ensure_minimum_days_between_password_changes_is_7_or_more" do
  title "Ensure minimum days between password changes is 7 or more"
  desc  "The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to prevent users from changing their password until a minimum number of days have passed since the last time the user changed their password. It is recommended that PASS_MIN_DAYS parameter be set to 7 or more days.\n\nRationale: By restricting the frequency of password changes, an administrator can prevent users from repeatedly changing their password in an attempt to circumvent password reuse controls."
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_MIN_DAYS\s+([789]|[1-9][0-9]+)\s*(\s+#.*)?$/) }
  end
  shadow.user(/.+/).entries.each do |entry|
    describe.one do
      describe entry do
        its("password") { should_not cmp(/^[^!*]/) }
      end
      describe entry do
        its("min_days") { should_not cmp < 7 }
      end
    end
  end
end

control "cis benchmark 5.4.1.3_Ensure_password_expiration_warning_days_is_7_or_more" do
  title "Ensure password expiration warning days is 7 or more"
  desc  "The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users that their password will expire in a defined number of days. It is recommended that the PASS_WARN_AGE parameter be set to 7 or more days.\n\nRationale: Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered."
  impact 1.0
  describe file("/etc/login.defs") do
    its("content") { should match(/^\s*PASS_WARN_AGE\s+([789]|[1-9][0-9]+)\s*(\s+#.*)?$/) }
  end
  shadow.user(/.+/).entries.each do |entry|
    describe.one do
      describe entry do
        its("passwords") { should_not cmp(/^[^!*]/) }
      end
      describe entry do
        its("warn_days") { should_not cmp < 7 }
      end
    end
  end
end

control "cis benchmark 5.4.1.4_Ensure_inactive_password_lock_is_30_days_or_less" do
  title "Ensure inactive password lock is 30 days or less"
  desc  "User accounts that have been inactive for over a given period of time can be automatically disabled. It is recommended that accounts that are inactive for 30 days after password expiration be disabled.\n\nRationale: Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies."
  impact 1.0
  describe file("/etc/default/useradd") do
    its("content") { should match(/^\s*INACTIVE\s*=\s*(30|[1-2][0-9]|[1-9])\s*(\s+#.*)?$/) }
  end
  shadow.user(/.+/).entries.each do |entry|
    describe.one do
      describe entry do
        its("passwords") { should_not cmp(/^[^!*]/) }
      end
      describe entry do
        its("inactive_days") { should_not cmp > 30 }
      end
    end
  end
end

control "cis benchmark 5.4.2_Ensure_system_accounts_are_non-login" do
  title "Ensure system accounts are non-login"
  desc  "There are a number of accounts provided with Ubuntu that are used to manage applications and are not intended to provide an interactive shell.\n\nRationale: It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, Ubuntu sets the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to /sbin/nologin. This prevents the account from potentially being used to run any commands."
  impact 1.0
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ } do
    its("entries") { should_not be_empty }
  end
  describe passwd.where { user =~ /^(?!root|sync|shutdown|halt).*$/ && uid.to_i < 1000 && shell != "/usr/sbin/nologin" } do
    its("entries") { should be_empty }
  end
end

control "cis benchmark 5.4.3_Ensure_default_group_for_the_root_account_is_GID_0" do
  title "Ensure default group for the root account is GID 0"
  desc  "The usermod command can be used to specify which group the root user belongs to. This affects permissions of files that are created by the root user.\n\nRationale: Using GID 0 for the  root account helps prevent  root -owned files from accidentally becoming accessible to non-privileged users."
  impact 1.0
  describe passwd.where { user == "root" } do
    its("entries") { should_not be_empty }
  end
  describe passwd.where { user == "root" && gid.to_i == 0 } do
    its("entries") { should_not be_empty }
  end
end

control "cis benchmark 5.4.4_Ensure_default_user_umask_is_027_or_more_restrictive" do
  title "Ensure default user umask is 027 or more restrictive"
  desc  "The default umask determines the permissions of files created by users. The user creating the file has the discretion of making their files and directories readable by others via the chmod command. Users who wish to allow their files and directories to be readable by others by default may choose a different default umask by inserting the umask command into the standard shell configuration files (.profile, .bashrc, etc.) in their home directories.\n\nRationale: Setting a very secure default value for umask ensures that users make a conscious choice about their file permissions. A default umask setting of 077 causes files and directories created by users to not be readable by any other user on the system. A umask of 027 would make files and directories readable by users in the same Unix group, while a umask of 022 would make files readable by every user on the system."
  impact 1.0
  describe file("/etc/bash.bashrc") do
    its("content") { should match(/^\s*umask\s+[01234567][2367]7\s*(\s+#.*)?$/) }
  end
  describe file("/etc/bash.bashrc") do
    its("content") { should_not match(/^\s*umask\s+[01234567](0[7654321]|[7654321][654321])\s*(\s+#.*)?$/) }
  end
  describe file("/etc/profile") do
    its("content") { should match(/^\s*umask\s+[01234567][2367]7\s*(\s+#.*)?$/) }
  end
  describe file("/etc/profile") do
    its("content") { should_not match(/^\s*umask\s+[01234567](0[7654321]|[7654321][654321])\s*(\s+#.*)?$/) }
  end
end

control "cis benchmark 5.6_Ensure_access_to_the_su_command_is_restricted" do
  title "Ensure access to the su command is restricted"
  desc  "The su command allows a user to run a command or shell as another user. The program has been superseded by sudo, which allows for more granular control over privileged access. Normally, the su command can be executed by any user. By uncommenting the pam_wheel.so statement in /etc/pam.d/su, the su command will only allow users in the wheel group to execute su.\n\nRationale: Restricting the use of su, and using sudo in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via sudo, whereas su can only record that a user executed the su program."
  impact 1.0
  describe file("/etc/pam.d/su") do
    its("content") { should match(/^\s*auth\s+required\s+pam_wheel.so\s+use_uid\s*$/) }
  end
end

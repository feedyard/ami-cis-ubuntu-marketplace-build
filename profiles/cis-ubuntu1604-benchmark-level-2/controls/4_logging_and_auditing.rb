# Controls mapped to CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0 12-28-2017
#
# Level 2 controls

control "cis benchmark 4.1.1.1_Ensure_audit_log_storage_size_is_configured" do
  title "Ensure audit log storage size is configured"
  desc  "Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be rotated and a new log file will be started.\n\nRationale: It is important that an appropriate size is determined for log files so that they do not impact the system and audit data is not lost."
  impact 0.0
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*max_log_file\s*=\s*\S+\s*(\s+#.*)?$/) }
  end
end

control "cis benchmark 4.1.1.2_Ensure_system_is_disabled_when_audit_logs_are_full" do
  title "Ensure system is disabled when audit logs are full"
  desc  "The auditd daemon can be configured to halt the system when the audit logs are full.\n\nRationale: In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the system's availability."
  impact 1.0
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*space_left_action\s*=\s*email\s*(\s+#.*)?$/) }
  end
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*action_mail_acct\s*=\s*root\s*(\s+#.*)?$/) }
  end
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*admin_space_left_action\s*=\s*halt\s*(\s+#.*)?$/) }
  end
end

control "cis benchmark 4.1.1.3_Ensure_audit_logs_are_not_automatically_deleted" do
  title "Ensure audit logs are not automatically deleted"
  desc  "The max_log_file_action setting determines how to handle the audit log file reaching the max file size. A value of keep_logs will rotate the logs but never delete old logs.\n\nRationale: In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing the audit history."
  impact 1.0
  describe file("/etc/audit/auditd.conf") do
    its("content") { should match(/^\s*max_log_file_action\s*=\s*keep_logs\s*(\s+#.*)?$/) }
  end
end

control "cis benchmark 4.1.2_Ensure_auditd_service_is_enabled" do
  title "Ensure auditd service is enabled"
  desc  "Turn on the auditd daemon to record system events.\n\nRationale: The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring."
  impact 1.0
  a = command("systemctl is-enabled auditd.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should match(/.+/) }
    end
  end
end

control "cis benchmark 4.1.3_Ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled" do
  title "Ensure auditing for processes that start prior to auditd is enabled"
  desc  "Configure grub so that processes that are capable of being audited can be audited even if they start up prior to auditd startup.\n\nRationale: Audit events need to be captured on processes that start up prior to auditd, so that potential malicious activity cannot go undetected."
  impact 1.0
  describe file("/boot/grub/grub.cfg") do
    its("content") { should match(/^\s*linux\S*(\s+\S+)+\s+audit=1/) }
  end
end

control "cis benchmark 4.s1.4_Ensure_events_that_modify_date_and_time_information_are_collected" do
  title "Ensure events that modify date and time information are collected"
  desc  "Capture events where the system date and/or time has been modified. The parameters in this section are set to determine if the adjtimex (tune kernel clock), settimeofday (Set time, using timeval and timezone structures) stime (using seconds since 1/1/1970) or clock_settime (allows for the setting of several internal clocks and timers) system calls have been executed and always write an audit record to the /var/log/audit.log file upon exit, tagging the records with the identifier \"time-change\"\n\nRationale: Unexpected changes in system date and/or time could be a sign of malicious activity on the system."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-S\s+stime\s+-k\s+time-change *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+clock_settime\s+-k\s+time-change *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/localtime\s+-p\s+wa\s+-k\s+time-change *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-k\s+time-change *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+clock_settime\s+-k\s+time-change *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "cis benchmark 4.1.5_Ensure_events_that_modify_usergroup_information_are_collected" do
  title "Ensure events that modify user/group information are collected"
  desc  "Record events affecting the group, passwd (user IDs), shadow and gshadow (passwords) or /etc/security/opasswd (old passwords, based on remember parameter in the PAM configuration) files. The parameters in this section will watch the files to see if they have been opened for write or have had attribute changes (e.g. permissions) and tag them with the identifier \"identity\" in the audit log file.\n\nRationale: Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/group\s+-p\s+wa\s+-k\s+identity *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/passwd\s+-p\s+wa\s+-k\s+identity *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/gshadow\s+-p\s+wa\s+-k\s+identity *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/shadow\s+-p\s+wa\s+-k\s+identity *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/security\/opasswd\s+-p\s+wa\s+-k\s+identity *$/) }
  end
end

control "cis benchmark 4.1.6_Ensure_events_that_modify_the_systems_network_environment_are_collected" do
  title "Ensure events that modify the system's network environment are collected"
  desc  "Record changes to network environment files or system calls. The below parameters monitor the sethostname (set the systems host name) or setdomainname (set the systems domainname) system calls, and write an audit event on system call exit. The other parameters monitor the /etc/issue and /etc/issue.net files (messages displayed pre-login), /etc/hosts (file containing host names and associated IP addresses) and /etc/sysconfig/network (directory containing network interface scripts and configurations) files.\n\nRationale: Monitoring sethostname and setdomainname will identify potential unauthorized changes to host and domainname of a system. The changing of these names could potentially break security parameters that are set based on those names. The /etc/hosts file is monitored for changes in the file that can indicate an unauthorized intruder is trying to change machine associations with IP addresses and trick users and processes into connecting to unintended machines. Monitoring /etc/issue and /etc/issue.net is important, as intruders could put disinformation into those files and trick users into providing information to the intruder. Monitoring /etc/sysconfig/network is important as it can show if network interfaces or scripts are being modified in a way that can lead to the machine becoming unavailable or compromised. All audit records will be tagged with the identifier \"system-locale.\""
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/issue\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/issue.net\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/hosts\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/network\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/networks\s+-p\s+wa\s+-k\s+system-locale *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "cis benchmark 4.1.7_Ensure_events_that_modify_the_systems_Mandatory_Access_Controls_are_collected" do
  title "Ensure events that modify the system's Mandatory Access Controls are collected"
  desc  "Monitor SELinux/AppArmor mandatory access controls. The parameters below monitor any write access (potential additional, deletion or modification of files in the directory) or attribute changes to the /etc/selinux or /etc/apparmor and /etc/apparmor.d directories.\n\nRationale: Changes to files in these directories could indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of the system."
  impact 1.0
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-w\s+\/etc\/selinux\/\s+-p\s+wa\s+-k\s+MAC-policy *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-w\s+\/etc\/apparmor\/\s+-p\s+wa\s+-k\s+MAC-policy *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-w\s+\/etc\/apparmor.d\/\s+-p\s+wa\s+-k\s+MAC-policy *$/) }
    end
  end
end

control "cis benchmark 4.1.8_Ensure_login_and_logout_events_are_collected" do
  title "Ensure login and logout events are collected"
  desc  "Monitor login and logout events. The parameters below track changes to files associated with login/logout events. The file /var/log/faillog tracks failed events from login. The file /var/log/lastlog maintain records of the last time a user successfully logged in. The file /var/log/tallylog maintains records of failures via the pam_tally2 module\n\nRationale: Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/faillog\s+-p\s+wa\s+-k\s+logins *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/lastlog\s+-p\s+wa\s+-k\s+logins *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/tallylog\s+-p\s+wa\s+-k\s+logins *$/) }
  end
end

control "cis benchmark 4.1.9_Ensure_session_initiation_information_is_collected" do
  title "Ensure session initiation information is collected"
  desc  "Monitor session initiation events. The parameters in this section track changes to the files associated with session events. The file /var/run/utmp file tracks all currently logged in users. The /var/log/wtmp file tracks logins, logouts, shutdown, and reboot events. All audit records will be tagged with the identifier \"session.\" The file /var/log/btmp keeps track of failed login attempts and can be read by entering the command /usr/bin/last -f /var/log/btmp. All audit records will be tagged with the identifier \"logins.\"\n\nRationale: Monitoring these files for changes could alert a system administrator to logins occurring at unusual hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally log in)."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/run\/utmp\s+-p\s+wa\s+-k\s+session *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/wtmp\s+-p\s+wa\s+-k\s+session *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/btmp\s+-p\s+wa\s+-k\s+session *$/) }
  end
end

control "cis benchmark 4.1.10_Ensure_discretionary_access_control_permission_modification_events_are_collected" do
  title "Ensure discretionary access control permission modification events are collected"
  desc  "Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. The chmod, fchmod and fchmodat system calls affect the permissions associated with a file. The chown, fchown, fchownat and lchown system calls affect owner and group attributes on a file. The setxattr, lsetxattr, fsetxattr (set extended file attributes) and removexattr, lremovexattr, fremovexattr (remove extended file attributes) control extended file attributes. In all cases, an audit record will only be written for non-system user ids (auid >= 1000) and will ignore Daemon events (auid = 4294967295). All audit records will be tagged with the identifier \"perm_mod.\"\n\nRationale: Monitoring for changes in file attributes could alert a system administrator to activity that could indicate intruder activity or policy violation."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "cis benchmark 4.1.11_Ensure_unsuccessful_unauthorized_file_access_attempts_are_collected" do
  title "Ensure unsuccessful unauthorized file access attempts are collected"
  desc  "Monitor for unsuccessful attempts to access files. The parameters below are associated with system calls that control creation (creat), opening (open, openat) and truncation (truncate, ftruncate) of files. An audit log record will only be written if the user is a non-privileged user (auid > = 1000), is not a Daemon event (auid=4294967295) and if the system call returned EACCES (permission denied to the file) or EPERM (some other permanent error associated with the specific system call). All audit records will be tagged with the identifier \"access.\"\n\nRationale: Failed attempts to open, create or truncate files could be an indication that an individual or process is trying to gain unauthorized access to the system."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access *$/) }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "cis benchmark 4.1.12_Ensure_use_of_privileged_commands_is_collected" do
  title "Ensure use of privileged commands is collected"
  desc  "Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to determine if unprivileged users are running these commands.\n\nRationale: Execution of privileged commands by non-privileged users could be an indication of someone trying to gain unauthorized access to the system."
  impact 1.0
  command("find / -regex .\\*/.\\+ -type f -perm /06000 -xdev").stdout.split.map { |x| "^\\-a (always,exit|exit,always) \\-F path=" + x.to_s }.map { |x| x.to_s + " \\-F perm=x \\-F auid>=1000 \\-F auid!=4294967295 \\-k privileged$" }.each do |entry|
    describe file("/etc/audit/audit.rules") do
      its("content") { should match Regexp.new(entry) }
    end
  end
end

control "cis benchmark 4.1.13_Ensure_successful_file_system_mounts_are_collected" do
  title "Ensure successful file system mounts are collected"
  desc  "Monitor the use of the mount system call. The mount (and umount) system call controls the mounting and unmounting of file systems. The parameters below configure the system to create an audit record when the mount system call is used by a non-privileged user\n\nRationale: It is highly unusual for a non privileged user to mount file systems to the system. While tracking mount commands gives the system administrator evidence that external media may have been mounted (based on a review of the source of the mount and confirming it's an external media type), it does not conclusively indicate that data was exported to the media. System administrators who wish to determine if data were exported, would also have to track successful open, creat and truncate system calls requiring write access to a file under the mount point of the external media file system. This could give a fair indication that a write occurred. The only way to truly prove it, would be to track successful writes to the external media. Tracking write system calls could quickly fill up the audit log and is not recommended. Recommendations on configuration options to track data export to media is beyond the scope of this document."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "cis benchmark 4.1.14_Ensure_file_deletion_events_by_users_are_collected" do
  title "Ensure file deletion events by users are collected"
  desc  "Monitor the use of system calls associated with the deletion or renaming of files and file attributes. This configuration statement sets up monitoring for the unlink (remove a file), unlinkat (remove a file attribute), rename (rename a file) and renameat (rename a file attribute) system calls and tags them with the identifier \"delete\".\n\nRationale: Monitoring these calls from non-privileged users could provide a system administrator with evidence that inappropriate removal of files and file attributes associated with protected files is occurring. While this audit option will look at all events, system administrators will want to look for specific privileged files that are being deleted or altered."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
  end
end

control "cis benchmark 4.1.15_Ensure_changes_to_system_administration_scope_sudoers_is_collected" do
  title "Ensure changes to system administration scope (sudoers) is collected"
  desc  "Monitor scope changes for system administrations. If the system has been properly configured to force system administrators to log in as themselves first and then use the sudo command to execute privileged commands, it is possible to monitor changes in scope. The file /etc/sudoers will be written to when the file or its attributes have changed. The audit records will be tagged with the identifier \"scope.\"\n\nRationale: Changes in the /etc/sudoers file can indicate that an unauthorized change has been made to scope of system administrator activity."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/sudoers\s+-p\s+wa\s+-k\s+scope *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/etc\/sudoers.d\s+-p\s+wa\s+-k\s+scope *$/) }
  end
end

control "cis benchmark 4.1.16_Ensure_system_administrator_actions_sudolog_are_collected" do
  title "Ensure system administrator actions (sudolog) are collected"
  desc  "Monitor the sudo log file. If the system has been properly configured to disable the use of the su command and force all administrators to have to log in first and then use sudo to execute privileged commands, then all administrator commands will be logged to /var/log/sudo.log. Any time a command is executed, an audit event will be triggered as the /var/log/sudo.log file will be opened for write and the executed administration command will be written to the log.\n\nRationale: Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file itself has been tampered with. Administrators will want to correlate the events written to the audit trail with the records written to /var/log/sudo.log to verify if unauthorized commands have been executed."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/var\/log\/sudo.log\s+-p\s+wa\s+-k\s+actions *$/) }
  end
end

control "cis benchmark 4.1.17_Ensure_kernel_module_loading_and_unloading_is_collected" do
  title "Ensure kernel module loading and unloading is collected"
  desc  "Monitor the loading and unloading of kernel modules. The programs insmod (install a kernel module), rmmod (remove a kernel module), and modprobe (a more sophisticated program to load and unload modules, as well as some other features) control loading and unloading of modules. The init_module (load a module) and delete_module (delete a module) system calls control loading and unloading of modules. Any execution of the loading and unloading module programs and system calls will trigger an audit record with an identifier of \"modules\".\n\nRationale: Monitoring the use of insmod, rmmod and modprobe could provide system administrators with evidence that an unauthorized user loaded or unloaded a kernel module, possibly compromising the security of the system. Monitoring of the init_module and delete_module system calls would reflect an unauthorized user attempting to use a different program to load and unload modules."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/sbin\/insmod\s+-p\s+x\s+-k\s+modules *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/sbin\/rmmod\s+-p\s+x\s+-k\s+modules *$/) }
  end
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-w\s+\/sbin\/modprobe\s+-p\s+x\s+-k\s+modules *$/) }
  end
  describe.one do
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+arch=b32\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should_not eq "x86_64" }
    end
    describe file("/etc/audit/audit.rules") do
      its("content") { should match(/^-a\s+(always,exit|exit,always)\s+arch=b64\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules *$/) }
    end
    describe command("uname -m").stdout do
      its("strip") { should eq "x86_64" }
    end
  end
end

control "cis benchmark 4.1.18_Ensure_the_audit_configuration_is_immutable" do
  title "Ensure the audit configuration is immutable"
  desc  "Set system audit so that audit rules cannot be modified with auditctl. Setting the flag \"-e 2\" forces audit to be put in immutable mode. Audit changes can only be made on system reboot.\n\nRationale: In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. Users would most likely notice a system reboot and that could alert administrators of an attempt to make unauthorized audit changes."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/^-e\s+2 *$/) }
  end
end

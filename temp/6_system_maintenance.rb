# Controls mapped to CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0 12-28-2017

control "cis benchmark 6.1.2_Ensure_permissions_on_etcpasswd_are_configured" do
  title "Ensure permissions on /etc/passwd are configured"
  desc  "The /etc/passwd file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate.\n\nRationale: It is critical to ensure that the /etc/passwd file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/passwd") do
    it { should exist }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/passwd") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/passwd") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/passwd") do
    its("sgid") { should equal false }
  end
  describe file("/etc/passwd") do
    its("sticky") { should equal false }
  end
  describe file("/etc/passwd") do
    its("suid") { should equal false }
  end
  describe file("/etc/passwd") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/passwd") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/passwd") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/passwd") do
    it { should be_writable.by "owner" }
  end
end

control "cis benchmark 6.1.3_Ensure_permissions_on_etcshadow_are_configured" do
  title "Ensure permissions on /etc/shadow are configured"
  desc  "The /etc/shadow file is used to store the information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the user accounts."
  impact 1.0
  describe file("/etc/shadow") do
    it { should exist }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/shadow") do
    its("gid") { should cmp 42 }
  end
  describe file("/etc/shadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/shadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/shadow") do
    its("sgid") { should equal false }
  end
  describe file("/etc/shadow") do
    its("sticky") { should equal false }
  end
  describe file("/etc/shadow") do
    its("suid") { should equal false }
  end
  describe file("/etc/shadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/shadow") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 6.1.4_Ensure_permissions_on_etcgroup_are_configured" do
  title "Ensure permissions on /etc/group are configured"
  desc  "The /etc/group file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else.\n\nRationale: The /etc/group file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs."
  impact 1.0
  describe file("/etc/group") do
    it { should exist }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/group") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/group") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/group") do
    its("sgid") { should equal false }
  end
  describe file("/etc/group") do
    its("sticky") { should equal false }
  end
  describe file("/etc/group") do
    its("suid") { should equal false }
  end
  describe file("/etc/group") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/group") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/group") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/group") do
    it { should be_writable.by "owner" }
  end
end

control "cis benchmark 6.1.5_Ensure_permissions_on_etcgshadow_are_configured" do
  title "Ensure permissions on /etc/gshadow are configured"
  desc  "The /etc/gshadow file is used to store the information about groups that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/gshadow file (such as group administrators) could also be useful to subvert the group."
  impact 1.0
  describe file("/etc/gshadow") do
    it { should exist }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/gshadow") do
    its("gid") { should cmp 42 }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/gshadow") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/gshadow") do
    its("sgid") { should equal false }
  end
  describe file("/etc/gshadow") do
    its("sticky") { should equal false }
  end
  describe file("/etc/gshadow") do
    its("suid") { should equal false }
  end
  describe file("/etc/gshadow") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/gshadow") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 6.1.6_Ensure_permissions_on_etcpasswd-_are_configured" do
  title "Ensure permissions on /etc/passwd- are configured"
  desc  "The /etc/passwd- file contains backup user account information.\n\nRationale: It is critical to ensure that the /etc/passwd- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/passwd-") do
    it { should exist }
  end
  describe file("/etc/passwd-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/passwd-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/passwd-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/passwd-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/passwd-") do
    its("sgid") { should equal false }
  end
  describe file("/etc/passwd-") do
    its("sticky") { should equal false }
  end
  describe file("/etc/passwd-") do
    its("suid") { should equal false }
  end
  describe file("/etc/passwd-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/passwd-") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 6.1.7_Ensure_permissions_on_etcshadow-_are_configured" do
  title "Ensure permissions on /etc/shadow- are configured"
  desc  "The  /etc/shadow-  file is used to store backup information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/shadow-") do
    it { should exist }
  end
  describe file("/etc/shadow-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/shadow-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/shadow-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/shadow-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/shadow-") do
    its("sgid") { should equal false }
  end
  describe file("/etc/shadow-") do
    its("sticky") { should equal false }
  end
  describe file("/etc/shadow-") do
    its("suid") { should equal false }
  end
  describe file("/etc/shadow-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/shadow-") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 6.1.8_Ensure_permissions_on_etcgroup-_are_configured" do
  title "Ensure permissions on /etc/group- are configured"
  desc  "The /etc/group- file contains a backup list of all the valid groups defined in the system.\n\nRationale: It is critical to ensure that the /etc/group- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/group-") do
    it { should exist }
  end
  describe file("/etc/group-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/group-") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/group-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/group-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/group-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/group-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/group-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/group-") do
    its("sgid") { should equal false }
  end
  describe file("/etc/group-") do
    its("sticky") { should equal false }
  end
  describe file("/etc/group-") do
    its("suid") { should equal false }
  end
  describe file("/etc/group-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/group-") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 6.1.9_Ensure_permissions_on_etcgshadow-_are_configured" do
  title "Ensure permissions on /etc/gshadow- are configured"
  desc  "The /etc/gshadow- file is used to store backup information about groups that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
  impact 1.0
  describe file("/etc/gshadow-") do
    it { should exist }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_readable.by "group" }
  end
  describe file("/etc/gshadow-") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_readable.by "other" }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/gshadow-") do
    its("sgid") { should equal false }
  end
  describe file("/etc/gshadow-") do
    its("sticky") { should equal false }
  end
  describe file("/etc/gshadow-") do
    its("suid") { should equal false }
  end
  describe file("/etc/gshadow-") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/gshadow-") do
    its("uid") { should cmp 0 }
  end
end

control "cis benchmark 6.1.10_Ensure_no_world_writable_files_exist" do
  title "Ensure no world writable files exist"
  desc  "Unix-based systems support variable settings to control access to files. World writable files are the least secure. See the chmod(2) man page for more information.\n\nRationale: Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity."
  impact 1.0

  describe 'Compensating Controls' do
    skip 'Compensating Control: Writable files support kubernetes configuration.'
  end
end

control "cis benchmark 6.1.11_Ensure_no_unowned_files_or_directories_exist" do
  title "Ensure no unowned files or directories exist"
  desc  "Sometimes when administrators delete users from the password file they neglect to remove all files owned by those users from the system.\n\nRationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended."
  impact 1.0

  describe 'Compensating Controls' do
    skip 'Compensating Control: No local users defined on nodes. Role permissions managed via pipelines.'
  end
end

control "cis benchmark 6.1.12_Ensure_no_ungrouped_files_or_directories_exist" do
  title "Ensure no ungrouped files or directories exist"
  desc  "Sometimes when administrators delete users or groups from the system they neglect to remove all files owned by those users or groups.\n\nRationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended."
  impact 1.0

  describe 'Compensating Controls' do
    skip 'Compensating Control: No local users defined on nodes. Role permissions managed via pipelines.'
  end
end

control "cis benchmark 6.1.13_Audit_SUID_executables" do
  title "Audit SUID executables"
  desc  "The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SUID program is to enable users to perform functions (such as changing their password) that require root privileges.\n\nRationale: There are valid reasons for SUID programs, but it is important to identify and review such programs to ensure they are legitimate."
  impact 0.0

  describe 'Compensating Controls' do
    skip 'Compensating Control: No local users defined on nodes. Role permissions managed via pipelines.'
  end
end

control "cis benchmark 6.1.14_Audit_SGID_executables" do
  title "Audit SGID executables"
  desc  "The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SGID program is to enable users to perform functions (such as changing their password) that require root privileges.\n\nRationale: There are valid reasons for SGID programs, but it is important to identify and review such programs to ensure they are legitimate. Review the files returned by the action in the audit section and check to see if system binaries have a different md5 checksum than what from the package. This is an indication that the binary may have been replaced."
  impact 0.0

  describe 'Compensating Controls' do
    skip 'Compensating Control: No local users defined on nodes. Role permissions managed via pipelines.'
  end
end

control "cis benchmark 6.2.1_Ensure_password_fields_are_not_empty" do
  title "Ensure password fields are not empty"
  desc  "An account with an empty password field means that anybody may log in as that user without providing a password.\n\nRationale: All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user."
  impact 1.0
  shadow.user(/.+/).entries.each do |entry|
    describe entry do
      its("password") { should cmp(/.+/) }
    end
  end
end

control "cis benchmark 6.2.2_Ensure_no_legacy__entries_exist_in_etcpasswd" do
  title "Ensure no legacy \"+\" entries exist in /etc/passwd"
  desc  "The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.\n\nRationale: These entries may provide an avenue for attackers to gain privileged access on the system."
  impact 1.0
  describe file("/etc/passwd") do
    its("content") { should_not match(/^\+:/) }
  end
end

control "cis benchmark 6.2.3_Ensure_no_legacy__entries_exist_in_etcshadow" do
  title "Ensure no legacy \"+\" entries exist in /etc/shadow"
  desc  "The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.\n\nRationale: These entries may provide an avenue for attackers to gain privileged access on the system."
  impact 1.0
  describe file("/etc/shadow") do
    its("content") { should_not match(/^\+:/) }
  end
end

control "cis benchmark 6.2.4_Ensure_no_legacy__entries_exist_in_etcgroup" do
  title "Ensure no legacy \"+\" entries exist in /etc/group"
  desc  "The character + in various files used to be markers for systems to insert data from NIS maps at a certain point in a system configuration file. These entries are no longer required on most systems, but may exist in files that have been imported from other platforms.\n\nRationale: These entries may provide an avenue for attackers to gain privileged access on the system."
  impact 1.0
  describe file("/etc/group") do
    its("content") { should_not match(/^\+:/) }
  end
end

control "cis benchmark 6.2.5_Ensure_root_is_the_only_UID_0_account" do
  title "Ensure root is the only UID 0 account"
  desc  "Any account with UID 0 has superuser privileges on the system.\n\nRationale: This access must be limited to only the default root account and only from the system console. Administrative access must be through an unprivileged account using an approved mechanism as noted in Item 5.6 Ensure access to the su command is restricted."
  impact 1.0
  describe file("/etc/passwd") do
    its("content") { should_not match(/^(?!root:)[^:]*:[^:]*:0/) }
  end
end

control "cis benchmark 6.2.6_Ensure_root_PATH_Integrity" do
  title "Ensure root PATH Integrity"
  desc  "The root user can execute any command on the system and could be fooled into executing programs unintentionally if the PATH is not set correctly.\n\nRationale: Including the current working directory (.) or other writable directory in root's executable path makes it likely that an attacker can gain superuser access by forcing an administrator operating as root to execute a Trojan horse program."
  impact 1.0
  describe os_env("PATH").content.to_s.split(":") do
    it { should_not be_empty }
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe entry do
      it { should_not eq "" }
    end
  end
  describe os_env("PATH").content.to_s.split(":") do
    it { should_not be_empty }
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe entry do
      it { should_not eq "." }
    end
  end
  os_env("PATH").content.to_s.split(":").each do |entry|
    describe file(entry) do
      it { should exist }
    end
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
    describe file(entry) do
      its("uid") { should cmp 0 }
    end
  end
end

control "cis benchmark 6.2.7_Ensure_all_users_home_directories_exist" do
  title "Ensure all users' home directories exist"
  desc  "Users can be defined in /etc/passwd without a home directory or with a home directory that does not actually exist.\n\nRationale: If the user's home directory does not exist or is unassigned, the user will be placed in \"/\" and will not be able to write any files or have local environment variables set."
  impact 1.0

  describe 'Compensating Controls' do
    skip 'Compensating Control: No local users defined on nodes. Role permissions managed via pipelines.'
  end
  # passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.each do |entry|
  #   describe file(entry) do
  #     it { should exist }
  #   end
  # end
end

control "cis benchmark 6.2.8_Ensure_users_home_directories_permissions_are_750_or_more_restrictive" do
  title "Ensure users' home directories permissions are 750 or more restrictive"
  desc  "While the system administrator can establish secure permissions for users' home directories, the users can easily override these.\n\nRationale: Group or world-writable user home directories may enable malicious users to steal or modify other users' data or to gain another user's system privileges."
  impact 1.0

  describe 'Compensating Controls' do
    skip 'Compensating Control: No local users defined on nodes. Role permissions managed via pipelines.'
  end
  # passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.each do |entry|
  #   describe file(entry) do
  #     it { should_not be_writable.by "group" }
  #   end
  #   describe file(entry) do
  #     it { should_not be_executable.by "other" }
  #   end
  #   describe file(entry) do
  #     it { should_not be_readable.by "other" }
  #   end
  #   describe file(entry) do
  #     it { should_not be_writable.by "other" }
  #   end
  # end
end

control "cis benchmark 6.2.9_Ensure_users_own_their_home_directories" do
  title "Ensure users own their home directories"
  desc  "The user home directory is space defined for the particular user to set local environment variables and to store personal files.\n\nRationale: Since the user is accountable for files stored in the user home directory, the user must be the owner of the directory."
  impact 1.0
  a = command("cat /etc/passwd | awk -F: '{ print $1 \" \" $3 \" \" $6 }' | while read user uid dir; do if [ $uid -ge 1000 -a -d \"$dir\" -a $user != \"nfsnobody\" ]; then owner=$(stat -L -c \"%U\" \"$dir\"); if [ \"$owner\" != \"$user\" ]; then echo \"The home directory ($dir) of user $user is owned by $owner.\"; fi; fi; done").stdout.scan(/.+/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 6.2.10_Ensure_users_dot_files_are_not_group_or_world_writable" do
  title "Ensure users' dot files are not group or world writable"
  desc  "While the system administrator can establish secure permissions for users' \"dot\" files, the users can easily override these.\n\nRationale: Group or world-writable user configuration files may enable malicious users to steal or modify other users' data or to gain another user's system privileges."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| command("find #{x} -maxdepth 1 -type f -regex '.*/\..+'").stdout.split }.flatten.each do |entry|
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
  end
end

control "cis benchmark 6.2.11_Ensure_no_users_have_.forward_files" do
  title "Ensure no users have .forward files"
  desc  "The .forward file specifies an email address to forward the user's mail to.\n\nRationale: Use of the .forward file poses a security risk in that sensitive data may be inadvertently transferred outside the organization. The .forward file also poses a risk as it can be used to execute commands that may perform unintended actions."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".forward"}.each do |entry|
    describe file(entry) do
      it { should_not exist }
    end
  end
end

control "cis benchmark 6.2.12_Ensure_no_users_have_.netrc_files" do
  title "Ensure no users have .netrc files"
  desc  "The .netrc file contains data for logging into a remote host for file transfers via FTP.\n\nRationale: The .netrc file presents a significant security risk since it stores passwords in unencrypted form. Even if FTP is disabled, user accounts may have brought over .netrc files from other systems which could pose a risk to those systems."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".netrc"}.each do |entry|
    describe file(entry) do
      it { should_not exist }
    end
  end
end

control "cis benchmark 6.2.13_Ensure_users_.netrc_Files_are_not_group_or_world_accessible" do
  title "Ensure users' .netrc Files are not group or world accessible"
  desc  "While the system administrator can establish secure permissions for users' .netrc files, the users can easily override these.\n\nRationale: .netrc files may contain unencrypted passwords that may be used to attack other systems."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".netrc"}.each do |entry|
    describe file(entry) do
      it { should_not be_executable.by "group" }
    end
    describe file(entry) do
      it { should_not be_readable.by "group" }
    end
    describe file(entry) do
      it { should_not be_writable.by "group" }
    end
    describe file(entry) do
      it { should_not be_executable.by "other" }
    end
    describe file(entry) do
      it { should_not be_readable.by "other" }
    end
    describe file(entry) do
      it { should_not be_writable.by "other" }
    end
  end
end

control "cis benchmark 6.2.14_Ensure_no_users_have_.rhosts_files" do
  title "Ensure no users have .rhosts files"
  desc  "While no .rhosts files are shipped by default, users can easily create them.\n\nRationale: This action is only meaningful if .rhosts support is permitted in the file /etc/pam.conf. Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf, they may have been brought over from other systems and could contain information useful to an attacker for those other systems."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.homes.map { |x| x.to_s.split(":") }.flatten.map { |x| x + '/' + ".rhosts"}.each do |entry|
    describe file(entry) do
      it { should_not exist }
    end
  end
end

control "cis benchmark 6.2.15_Ensure_all_groups_in_etcpasswd_exist_in_etcgroup" do
  title "Ensure all groups in /etc/passwd exist in /etc/group"
  desc  "Over time, system administration errors and changes can lead to groups being defined in /etc/passwd but not in /etc/group.\n\nRationale: Groups defined in the /etc/passwd file but not in the /etc/group file pose a threat to system security since group permissions are not properly managed."
  impact 1.0
  passwd.where { user =~ /^(?!root|halt|sync|shutdown).*/ }.where { shell != "/sbin/nologin" }.gids.map { |x| "^[^:]*:[^:]*:" + x.to_s }.map { |x| x.to_s + ":[^:]*$" }.each do |entry|
    describe file("/etc/group") do
      its("content") { should match Regexp.new(entry) }
    end
  end
end

control "cis benchmark 6.2.16_Ensure_no_duplicate_UIDs_exist" do
  title "Ensure no duplicate UIDs exist"
  desc  "Although the useradd program will not let you create a duplicate User ID (UID), it is possible for an administrator to manually edit the /etc/passwd file and change the UID field.\n\nRationale: Users must be assigned unique UIDs for accountability and to ensure appropriate access protections."
  impact 1.0
  describe passwd.where { user =~ /.*/ }.uids do
    its("length") { should_not eq 0 }
  end
  a = passwd.where { user =~ /.*/ }.uids.uniq.length
  describe passwd.where { user =~ /.*/ }.uids do
    its("length") { should cmp == a }
  end
end

control "cis benchmark 6.2.17_Ensure_no_duplicate_GIDs_exist" do
  title "Ensure no duplicate GIDs exist"
  desc  "Although the groupadd program will not let you create a duplicate Group ID (GID), it is possible for an administrator to manually edit the /etc/group file and change the GID field.\n\nRationale: User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections."
  impact 1.0
  describe file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten do
    its("length") { should_not eq 0 }
  end
  a = file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten.uniq.length
  describe file("/etc/group").content.to_s.scan(/^[^:]+:[^:]+:([\d]+):[^:]*$/).flatten do
    its("length") { should cmp == a }
  end
end

control "cis benchmark 6.2.18_Ensure_no_duplicate_user_names_exist" do
  title "Ensure no duplicate user names exist"
  desc  "Although the useradd program will not let you create a duplicate user name, it is possible for an administrator to manually edit the /etc/passwd file and change the user name.\n\nRationale: If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in /etc/passwd. For example, if \"test4\" has a UID of 1000 and a subsequent \"test4\" entry has a UID of 2000, logging in as \"test4\" will use UID 1000. Effectively, the UID is shared, which is a security problem."
  impact 1.0
  describe file("/etc/passwd").content.to_s.scan(/^([^:]+):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$/).flatten do
    its("length") { should_not eq 0 }
  end
  a = file("/etc/passwd").content.to_s.scan(/^([^:]+):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$/).flatten.uniq.length
  describe file("/etc/passwd").content.to_s.scan(/^([^:]+):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$/).flatten do
    its("length") { should cmp == a }
  end
end

control "cis benchmark 6.2.19_Ensure_no_duplicate_group_names_exist" do
  title "Ensure no duplicate group names exist"
  desc  "Although the groupadd program will not let you create a duplicate group name, it is possible for an administrator to manually edit the /etc/group file and change the group name.\n\nRationale: If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in /etc/group. Effectively, the GID is shared, which is a security problem."
  impact 1.0
  describe file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten do
    its("length") { should_not eq 0 }
  end
  a = file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten.uniq.length
  describe file("/etc/group").content.to_s.scan(/^([^:]+):[^:]+:[\d]+:[^:]*$/).flatten do
    its("length") { should cmp == a }
  end
end

control "cis benchmark 6.2.20_Ensure_shadow_group_is_empty" do
  title "Ensure shadow group is empty"
  desc  "The shadow group allows system programs which require access the ability to read the /etc/shadow file. No users should be assigned to the shadow group.\n\nRationale: Any users assigned to the shadow group would be granted read access to the /etc/shadow file. If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed passwords to break them. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert additional user accounts."
  impact 1.0
  describe file("/etc/group") do
    its("content") { should_not match(/^shadow:[^:]*:[^:]*:[^:]+$/) }
  end
end

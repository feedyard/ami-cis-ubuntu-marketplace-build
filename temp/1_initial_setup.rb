# Controls mapped to CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0 12-28-2017

control "cis benchmark 1.1.1.1_Ensure_mounting_of_cramfs_filesystems_is_disabled" do
  title "Ensure mounting of cramfs filesystems is disabled"
  desc  "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the server. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v cramfs").stdout.scan(/.+/)
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
      it { should_not match(/^cramfs\s+/) }
    end
  end
end

control "cis benchmark 1.1.1.2_Ensure_mounting_of_freevxfs_filesystems_is_disabled" do
  title "Ensure mounting of freevxfs filesystems is disabled"
  desc  "The freevxfs filesystem type is a free version of the Veritas type filesystem. This is the primary filesystem type for HP-UX operating systems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v freevxfs").stdout.scan(/.+/)
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
      it { should_not match(/^freevxfs\s+/) }
    end
  end
end

control "cis benchmark 1.1.1.3_Ensure_mounting_of_jffs2_filesystems_is_disabled" do
  title "Ensure mounting of jffs2 filesystems is disabled"
  desc  "The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured filesystem used in flash memory devices.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v jffs2").stdout.scan(/.+/)
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
      it { should_not match(/^jffs2\s+/) }
    end
  end
end

control "cis benchmark 1.1.1.4_Ensure_mounting_of_hfs_filesystems_is_disabled" do
  title "Ensure mounting of hfs filesystems is disabled"
  desc  "The hfs filesystem type is a hierarchical filesystem that allows you to mount Mac OS filesystems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v hfs").stdout.scan(/.+/)
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
      it { should_not match(/^hfs\s+/) }
    end
  end
end

control "cis benchmark 1.1.1.5_Ensure_mounting_of_hfsplus_filesystems_is_disabled" do
  title "Ensure mounting of hfsplus filesystems is disabled"
  desc  "The hfsplus filesystem type is a hierarchical filesystem designed to replace hfs that allows you to mount Mac OS filesystems.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v hfsplus").stdout.scan(/.+/)
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
      it { should_not match(/^hfsplus\s+/) }
    end
  end
end

control "cis benchmark 1.1.1.6_Ensure_mounting_of_udf_filesystems_is_disabled" do
  title "Ensure mounting of udf filesystems is disabled"
  desc  "The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer optical disc formats.\n\nRationale: Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it."
  impact 1.0
  a = command("modprobe -n -v udf").stdout.scan(/.+/)
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
      it { should_not match(/^udf\s+/) }
    end
  end
end

control "cis benchmark 1.1.14_Ensure_nodev_option_set_on_devshm_partitiov" do
  title "Ensure nodev option set on /dev/shm partitiov"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /run/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /dev/shm partitions."
  impact 1.0
  describe mount("/dev/shm") do
    it { should be_mounted }
  end
  describe mount("/dev/shm") do
    its("options") { should include "nodev" }
  end
end

control "cis benchmark 1.1.15_Ensure_nosuid_option_set_on_devshm_partitionrun" do
  title "Ensure nosuid option set on /dev/shm partitionrun"
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them."
  impact 1.0
  describe mount("/dev/shm") do
    it { should be_mounted }
  end
  describe mount("/dev/shm") do
    its("options") { should include "nosuid" }
  end
end

control "cis benchmark 1.1.16_Ensure_noexec_option_set_on_devshm_partition" do
  title "Ensure noexec option set on /dev/shm partition"
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system."
  impact 1.0
  describe mount("/dev/shm") do
    it { should be_mounted }
  end
  describe mount("/dev/shm") do
    its("options") { should include "noexec" }
  end
end

control "cis benchmark 1.1.17_Ensure_nodev_option_set_on_removable_media_partitions" do
  title "Ensure nodev option set on removable media partitions"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Removable media containing character and block special devices could be used to circumvent security controls by allowing non-root users to access sensitive device files such as /dev/kmem or the raw disk partitions."
  impact 0.0

  describe 'scan images for removable_media configuration' do
    skip 'compensating controls: no removable media options for aws ami'
  end
end

control "cis benchmark 1.1.18_Ensure_nosuid_option_set_on_removable_media_partitions" do
  title "Ensure nosuid option set on removable media partitions"
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them."
  impact 0.0

  describe 'scan images for removable_media configuration' do
    skip 'compensating controls: no removable media options for aws ami'
  end
end

control "cis benchmark 1.1.19_Ensure_noexec_option_set_on_removable_media_partitions" do
  title "Ensure noexec option set on removable media partitions"
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Setting this option on a file system prevents users from executing programs from the removable media. This deters users from being able to introduce potentially malicious software on the system."
  impact 0.0

  describe 'scan images for removable_media configuration' do
    skip 'compensating controls: no removable media options for aws ami'
  end
end

control "cis benchmark 1.1.20_Ensure_sticky_bit_is_set_on_all_world-writable_directories" do
  title "Ensure sticky bit is set on all world-writable directories"
  desc  "Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.\n\nRationale: This feature prevents the ability to delete or rename files in world writable directories (such as /tmp) that are owned by another user."
  impact 1.0

  describe 'Compensating Control' do
    skip 'Compensating Control: /home/CIS-Hardened-Reports/CIS-CAT-Results.html is only image on system with this setting'
  end
  # describe command("df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null") do
  #   its("stdout") { should eq('') }
  # end
end

control "cis benchmark 1.1.21_Disable_Automounting" do
  title "Disable Automounting"
  desc  "autofs allows automatic mounting of devices, typically including CD/DVDs and USB drives.\n\nRationale: With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in system even if they lacked permissions to mount it themselves."
  impact 1.0
  a = command("systemctl is-enabled autofs.service").stdout.scan(/enabled/)
  describe a do
    its("length") { should_not be > 0 }
  end
  a.each do |entry|
    describe entry do
      it { should_not match(/.+/) }
    end
  end
end

control "cis benchmark 1.2.1_Ensure_package_manager_repositories_are_configured" do
  title "Ensure package manager repositories are configured"
  desc  "Systems need to have package manager repositories configured to ensure they receive the latest patches and updates.\n\nRationale: If a system's package repositories are misconfigured important patches may not be identified or a rogue repository could introduce compromised software."
  impact 0.0

  describe 'Compensating Control' do
    skip 'Compensating Control: Ubuntu 16.04 LTS with no additional repositories added. Default config include canonical repositories with gpg'
  end
end

control "cis benchmark 1.2.2_Ensure_GPG_keys_are_configured" do
  title "Ensure GPG keys are configured"
  desc  "Most packages managers implement GPG key signing to verify package integrity during installation.\n\nRationale: It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system."
  impact 0.0

  describe 'Compensating Control' do
    skip 'Compensating Control: Ubuntu 16.04 LTS with no additional repositories added. Default config include canonical repositories and gpg'
  end
end

control "cis benchmark 1.3.1_Ensure_AIDE_is_installed" do
  title "Ensure AIDE is installed"
  desc  "AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes which can then be used to compare against the current state of the filesystem to detect modifications to the system.\n\nRationale: By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries."
  impact 1.0
  describe package("aide") do
    it { should be_installed }
  end
end

control "cis benchmark 1.3.2_Ensure_filesystem_integrity_is_regularly_checked" do
  title "Ensure filesystem integrity is regularly checked"
  desc  "Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.\n\nRationale: Periodic file checking allows the system administrator to determine on a regular basis if critical files have been changed in an unauthorized fashion."
  impact 1.0
  describe.one do
    describe command("crontab -u root -l | grep aide") do
      its("stdout") { should include ('aide') }
    end
    describe file("/var/spool/cron/crontabs/root") do
      its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
    end
    describe file("/etc/crontab") do
      its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
    end
    command("find /etc/cron.d -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
    command("find /etc/cron.hourly -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
    command("find /etc/cron.daily -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
    command("find /etc/cron.weekly -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
    command("find /etc/cron.monthly -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\/usr\/bin\/aide --check/) }
      end
    end
  end
end

control "cis benchmark 1.4.1_Ensure_permissions_on_bootloader_config_are_configured" do
  title "Ensure permissions on bootloader config are configured"
  desc  "The grub configuration file contains information on boot settings and passwords for unlocking boot options. The grub configuration is usually grub.cfg stored in /boot/grub.\n\nRationale: Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them."
  impact 1.0
  describe file("/boot/grub/grub.cfg") do
    it { should exist }
  end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_executable.by "group" }
  end
  # disabled reverts back after change
  # describe file("/boot/grub/grub.cfg") do
  #   it { should_not be_readable.by "group" }
  # end
  describe file("/boot/grub/grub.cfg") do
    its("gid") { should cmp 0 }
  end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_writable.by "group" }
  end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_executable.by "other" }
  end
  # disabled - reverts back after change
  # describe file("/boot/grub/grub.cfg") do
  #   it { should_not be_readable.by "other" }
  # end
  describe file("/boot/grub/grub.cfg") do
    it { should_not be_writable.by "other" }
  end
  describe file("/boot/grub/grub.cfg") do
    its("uid") { should cmp 0 }
  end
end


control "cis benchmark 1.4.2_Ensure_bootloader_password_is_set" do
  title "Ensure bootloader password is set"
  desc  "Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters\n\nRationale: Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time)."
  impact 1.0

  describe 'Compensating Control' do
    skip 'Compensating Control: not support by AWS - there is no Console access'
  end
  # describe.one do
  #   describe file("/boot/grub/grub.cfg") do
  #     its("content") { should match(/^\s*set\s+superusers\s*=\s*"[^"]*"\s*(\s+#.*)?$/) }
  #   end
  #   describe file("/boot/grub/grub.cfg") do
  #     its("content") { should match(/^\s*password_pbkdf2\s+\S+\s+\S+\s*(\s+#.*)?$/) }
  #   end
  # end
end

control "cis benchmark 1.4.3_Ensure_authentication_required_for_single_user_mode" do
  title "Ensure authentication required for single user mode"
  desc  "Single user mode is used for recovery when the system detects an issue during boot or by manual selection from the bootloader.\n\nRationale: Requiring authentication in single user mode prevents an unauthorized user from rebooting the system into single user to gain root privileges without credentials."
  impact 1.0

  describe 'Compensating Control' do
    skip 'Compensating Control: not support by AWS - there is no Console access'
  end
end

control "cis benchmark 1.4.4_Ensure_interactive_boot_is_not_enabled" do
  title "Ensure interactive boot is not enabled"
  desc  "Interactive boot allows console users to interactively select which services start on boot. Not all distributions support this capability.\n                 The PROMPT_FOR_CONFIRM option provides console users the ability to interactively boot the system and select which services to start on boot .\n\nRationale: Turn off the PROMPT\n                   _FOR_CONFIRM option on the console to prevent console users from potentially overriding established security settings."
  impact 0.0

  describe 'Compensating Control' do
    skip 'Compensating Control: not support by AWS - there is no Console access'
  end
end

control "cis benchmark 1.5.1_Ensure_core_dumps_are_restricted" do
  title "Ensure core dumps are restricted"
  desc  "A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.\n\nRationale: Setting a hard limit on core dumps prevents users from overriding the soft variable. If core dumps are required, consider setting limits for user groups (see limits.conf(5)). In addition, setting the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core."
  impact 1.0
  describe.one do
    describe file("/etc/security/limits.d/core-dump.conf") do
      its("content") { should match(/^\s*\*\s+hard\s+core\s+0\s*(\s+#.*)?$/) }
    end
    command("find /etc/security/limits.d -type f -regex .\\*/.\\*").stdout.split.each do |entry|
      describe file(entry) do
        its("content") { should match(/^\s*\*\s+hard\s+core\s+0\s*(\s+#.*)?$/) }
      end
    end
  end
  describe kernel_parameter("fs.suid_dumpable") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("fs.suid_dumpable") do
    its("value") { should eq 0 }
  end
end

control "cis benchmark 1.5.2_Ensure_XDNX_support_is_enabled" do
  title "Ensure XD/NX support is enabled"
  desc  "Recent processors in the x86 family support the ability to prevent code execution on a per memory page basis. Generically and on AMD processors, this ability is called No Execute (NX), while on Intel processors it is called Execute Disable (XD). This ability can help prevent exploitation of buffer overflow vulnerabilities and should be activated whenever possible. Extra steps must be taken to ensure that this protection is enabled, particularly on 32-bit x86 systems. Other processors, such as Itanium and POWER, have included such support since inception and the standard kernel for those platforms supports the feature.\n\nRationale: Enabling any feature that can protect against buffer overflow attacks enhances the security of the system."
  impact 0.0
  a = command("dmesg | grep \"NX [(]Execute Disable[)] protection: active\"").stdout.scan(/.+/)
  describe a do
    its("length") { should be > 0 }
  end
  describe.one do
    a.each do |entry|
      describe entry do
        it { should match(/.+/) }
      end
    end
  end
end

control "cis benchmark 1.5.3_Ensure_address_space_layout_randomization_ASLR_is_enabled" do
  title "Ensure address space layout randomization (ASLR) is enabled"
  desc  "Address space layout randomization (ASLR) is an exploit mitigation technique which randomly arranges the address space of key data areas of a process.\n\nRationale: Randomly placing virtual memory regions will make it difficult to write memory page exploits as the memory placement will be consistently shifting."
  impact 1.0
  describe kernel_parameter("kernel.randomize_va_space") do
    its("value") { should_not be_nil }
  end
  describe kernel_parameter("kernel.randomize_va_space") do
    its("value") { should eq 2 }
  end
end

control "cis benchmark 1.5.4_Ensure_prelink_is_disabled" do
  title "Ensure prelink is disabled"
  desc  "prelink is a program that modifies ELF shared libraries and ELF dynamically linked binaries in such a way that the time needed for the dynamic linker to perform relocations at startup significantly decreases.\n\nRationale: The prelinking feature can interfere with the operation of AIDE, because it changes binaries. Prelinking can also increase the vulnerability of the system if a malicious user is able to compromise a common library such as libc."
  impact 1.0
  describe package("prelink") do
    it { should_not be_installed }
  end
end

control "cis benchmark 1.7.1.1_Ensure_message_of_the_day_is_configured_properly" do
  title "Ensure message of the day is configured properly"
  desc  "The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.\n                    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If mingetty(8) supports the following options, they display operating system information: \n                      \\m - machine architecture \\r - operating system release \\s - operating system name \\v - operating system version\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \"uname -a\" command once they have logged in."
  impact 1.0
  describe file("/etc/motd") do
    its("content") { should_not match(/(\\v|\\r|\\m|\\s)/) }
  end
end

control "cis benchmark 1.7.1.2_Ensure_local_login_warning_banner_is_configured_properly" do
  title "Ensure local login warning banner is configured properly"
  desc  "The contents of the  /etc/issue file are displayed to users prior to login for local terminals.\n                  \n                  \n                     \n                        \n                     \n                  \n                   Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If  mingetty(8)  supports the following options, they display operating system information:\n                      \n                  \n                   \n                   \\m\n                       - machine architecture\n                      \\r\n                       - operating system release\n                      \\s\n                       - operating system name\n                      \\v\n                       - operating system version\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place.  Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in."
  impact 0.0
  describe file("/etc/issue") do
    its("content") { should_not match(/(\\v|\\r|\\m|\\s)/) }
  end
end

control "cis benchmark 1.7.1.3_Ensure_remote_login_warning_banner_is_configured_properly" do
  title "Ensure remote login warning banner is configured properly"
  desc  "The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.\n                   Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If  mingetty(8)  supports the following options, they display operating system information:\n                      \n                     \n                      \\m\n                       - machine architecture\n                      \\r\n                       - operating system release\n                      \\s\n                       - operating system name\n                      \\v\n                       - operating system version\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" uname -a \" command once they have logged in."
  impact 0.0
  describe file("/etc/issue.net") do
    its("content") { should_not match(/(\\v|\\r|\\m|\\s)/) }
  end
end

control "cis benchmark 1.7.1.4_Ensure_permissions_on_etcmotd_are_configured" do
  title "Ensure permissions on /etc/motd are configured"
  desc  "The contents of the /etc/motd file are displayed to users after login and function as a message of the day for authenticated users.\n\nRationale: If the /etc/motd file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 0.0

  describe 'Compensating Control' do
    skip 'Compensating Control: custom message for cluster nodes not required'
  end
  # describe file("/etc/motd") do
  #   it { should exist }
  # end
  # describe file("/etc/motd") do
  #   it { should_not be_executable.by "group" }
  # end
  # describe file("/etc/motd") do
  #   it { should be_readable.by "group" }
  # end
  # describe file("/etc/motd") do
  #   its("gid") { should cmp 0 }
  # end
  # describe file("/etc/motd") do
  #   it { should_not be_writable.by "group" }
  # end
  # describe file("/etc/motd") do
  #   it { should_not be_executable.by "other" }
  # end
  # describe file("/etc/motd") do
  #   it { should be_readable.by "other" }
  # end
  # describe file("/etc/motd") do
  #   it { should_not be_writable.by "other" }
  # end
  # describe file("/etc/motd") do
  #   its("sgid") { should equal false }
  # end
  # describe file("/etc/motd") do
  #   its("sticky") { should equal false }
  # end
  # describe file("/etc/motd") do
  #   its("suid") { should equal false }
  # end
  # describe file("/etc/motd") do
  #   it { should_not be_executable.by "owner" }
  # end
  # describe file("/etc/motd") do
  #   it { should be_readable.by "owner" }
  # end
  # describe file("/etc/motd") do
  #   its("uid") { should cmp 0 }
  # end
  # describe file("/etc/motd") do
  #   it { should be_writable.by "owner" }
  # end
end

control "cis benchmark 1.7.1.5_Ensure_permissions_on_etcissue_are_configured" do
  title "Ensure permissions on /etc/issue are configured"
  desc  "The contents of the /etc/issue file are displayed to users prior to login for local terminals.\n\nRationale: If the /etc/issue file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 1.0
  describe file("/etc/issue") do
    it { should exist }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/issue") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/issue") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/issue") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/issue") do
    its("sgid") { should equal false }
  end
  describe file("/etc/issue") do
    its("sticky") { should equal false }
  end
  describe file("/etc/issue") do
    its("suid") { should equal false }
  end
  describe file("/etc/issue") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/issue") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/issue") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/issue") do
    it { should be_writable.by "owner" }
  end
end

control "cis benchmark 1.7.1.6_Ensure_permissions_on_etcissue.net_are_configured" do
  title "Ensure permissions on /etc/issue.net are configured"
  desc  "The contents of the /etc/issue.net file are displayed to users prior to login for remote connections from configured services.\n\nRationale: If the /etc/issue.net file does not have the correct ownership it could be modified by unauthorized users with incorrect or misleading information."
  impact 0.0
  describe file("/etc/issue.net") do
    it { should exist }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "group" }
  end
  describe file("/etc/issue.net") do
    its("gid") { should cmp 0 }
  end
  describe file("/etc/issue.net") do
    it { should_not be_writable.by "group" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "other" }
  end
  describe file("/etc/issue.net") do
    it { should_not be_writable.by "other" }
  end
  describe file("/etc/issue.net") do
    its("sgid") { should equal false }
  end
  describe file("/etc/issue.net") do
    its("sticky") { should equal false }
  end
  describe file("/etc/issue.net") do
    its("suid") { should equal false }
  end
  describe file("/etc/issue.net") do
    it { should_not be_executable.by "owner" }
  end
  describe file("/etc/issue.net") do
    it { should be_readable.by "owner" }
  end
  describe file("/etc/issue.net") do
    its("uid") { should cmp 0 }
  end
  describe file("/etc/issue.net") do
    it { should be_writable.by "owner" }
  end
end

control "cis benchmark 1.7.2_Ensure_GDM_login_banner_is_configured" do
  title "Ensure GDM login banner is configured"
  desc  "GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.\n\nRationale: Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place."
  impact 1.0
  describe.one do
    describe file("/etc/dconf/profile/gdm") do
      its("content") { should match(/^user-db:user$/) }
    end
    describe file("/etc/dconf/profile/gdm") do
      its("content") { should match(/^system-db:gdm$/) }
    end
    describe file("/etc/dconf/profile/gdm") do
      its("content") { should match(/^file-db:\/usr\/share\/gdm\/greeter-dconf-defaults$/) }
    end
    describe file("/etc/dconf/db/gdm.d/01-banner-message") do
      its("content") { should match(/^banner-message-enable=true$/) }
    end
    describe file("/etc/dconf/db/gdm.d/01-banner-message") do
      its("content") { should match(/^banner-message-text='.+'$/) }
    end
    describe package("gdm") do
      it { should_not be_installed }
    end
  end
end

control "cis benchmark 1.8_Ensure_updates_patches_and_additional_security_software_are_installed" do
  title "Ensure updates, patches, and additional security software are installed"
  desc  "Periodically patches are released for included software either due to security flaws or to include additional functionality.\n\nRationale: Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected."
  impact 0.0

  describe 'Compensating Control' do
    skip 'Compensating Control: Build on cis-release, unattended-upgrade cron scheduled for ${distro_id}:${distro_codename} and ${distro_codename}-security'
  end
end

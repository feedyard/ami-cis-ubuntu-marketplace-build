# Controls mapped to CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0 12-28-2017
#
# Level 2 controls

control "cis benchmark 1.1.2_Ensure_separate_partition_exists_for_tmp" do
  title "Ensure separate partition exists for /tmp"
  desc  "The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n\nRationale: Since the /tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /tmp its own file system allows an administrator to set the noexec option on the mount, making /tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
end

control "cis benchmark 1.1.3_Ensure_nodev_option_set_on_tmp_partition" do
  title "Ensure nodev option set on /tmp partition"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /tmp."
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "nodev" }
  end
end

control "cis benchmark 1.1.4_Ensure_nosuid_option_set_on_tmp_partition" do
  title "Ensure nosuid option set on /tmp partition"
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /tmp."
  impact 1.0
  describe mount("/tmp") do
    it { should be_mounted }
  end
  describe mount("/tmp") do
    its("options") { should include "nosuid" }
  end
end

control "cis benchmark 1.1.5_Ensure_separate_partition_exists_for_var" do
  title "Ensure separate partition exists for /var"
  desc  "The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.\n\nRationale: Since the /var directory may contain world-writable files and directories, there is a risk of resource exhaustion if it is not bound to a separate partition."
  impact 1.0
  describe mount("/var") do
    it { should be_mounted }
  end
end

control "cis benchmark 1.1.6_Ensure_separate_partition_exists_for_vartmp" do
  title "Ensure separate partition exists for /var/tmp"
  desc  "The /var/tmp directory is a world-writable directory used for temporary storage by all users and some applications.\n\nRationale: Since the /var/tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition. In addition, making /var/tmp its own file system allows an administrator to set the noexec option on the mount, making /var/tmp useless for an attacker to install executable code. It would also prevent an attacker from establishing a hardlink to a system setuid program and wait for it to be updated. Once the program was updated, the hardlink would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw."
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
end

control "cis benchmark 1.1.7_Ensure_nodev_option_set_on_vartmp_partition" do
  title "Ensure nodev option set on /var/tmp partition"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the /var/tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /var/tmp."
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
  describe mount("/var/tmp") do
    its("options") { should include "nodev" }
  end
end

control "cis benchmark 1.1.8_Ensure_nosuid_option_set_on_vartmp_partition" do
  title "Ensure nosuid option set on /var/tmp partition"
  desc  "The nosuid mount option specifies that the filesystem cannot contain setuid files.\n\nRationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot create setuid files in /var/tmp."
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
  describe mount("/var/tmp") do
    its("options") { should include "nosuid" }
  end
end

control "cis benchmark 1.1.9_Ensure_noexec_option_set_on_vartmp_partition" do
  title "Ensure noexec option set on /var/tmp partition"
  desc  "The noexec mount option specifies that the filesystem cannot contain executable binaries.\n\nRationale: Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /var/tmp."
  impact 1.0
  describe mount("/var/tmp") do
    it { should be_mounted }
  end
  describe mount("/var/tmp") do
    its("options") { should include "noexec" }
  end
end

control "cis benchmark 1.1.10_Ensure_separate_partition_exists_for_varlog" do
  title "Ensure separate partition exists for /var/log"
  desc  "The /var/log directory is used by system services to store log data .\n\nRationale: There are two important reasons to ensure that system logs are stored on a separate partition: protection against resource exhaustion (since logs can grow quite large) and protection of audit data."
  impact 1.0
  describe mount("/var/log") do
    it { should be_mounted }
  end
end

control "cis benchmark 1.1.11_Ensure_separate_partition_exists_for_varlogaudit" do
  title "Ensure separate partition exists for /var/log/audit"
  desc  "The auditing daemon, auditd, stores log data in the /var/log/audit directory.\n\nRationale: There are two important reasons to ensure that data gathered by auditd is stored on a separate partition: protection against resource exhaustion (since the audit.log file can grow quite large) and protection of audit data. The audit daemon calculates how much free space is left and performs actions based on the results. If other processes (such as syslog) consume space in the same partition as auditd, it may not perform as desired."
  impact 1.0
  describe mount("/var/log/audit") do
    it { should be_mounted }
  end
end

control "cis benchmark 1.1.12_Ensure_separate_partition_exists_for_home" do
  title "Ensure separate partition exists for /home"
  desc  "The /home directory is used to support disk storage needs of local users.\n\nRationale: If the system is intended to support local users, create a separate partition for the /home directory to protect against resource exhaustion and restrict the type of files that can be stored under /home."
  impact 1.0
  describe mount("/home") do
    it { should be_mounted }
  end
end

control "cis benchmark 1.1.13_Ensure_nodev_option_set_on_home_partition" do
  title "Ensure nodev option set on /home partition"
  desc  "The nodev mount option specifies that the filesystem cannot contain special devices.\n\nRationale: Since the user partitions are not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices."
  impact 1.0
  describe mount("/home") do
    it { should be_mounted }
  end
  describe mount("/home") do
    its("options") { should include "nodev" }
  end
end


control "cis benchmark 1.6.1.1_Ensure_SELinux_is_not_disabled_in_bootloader_configuration" do
  title "Ensure SELinux is not disabled in bootloader configuration"
  desc  "Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.\n\nRationale: SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden."
  impact 1.0
  describe.one do
    describe file("/boot/grub/grub.cfg") do
      its("content") { should_not match(/^\s*linux\S*(\s+\S+)+\s+selinux=0/) }
    end
    describe file("/boot/grub/grub.cfg") do
      its("content") { should_not match(/^\s*linux\S*(\s+\S+)+\s+enforcing=0/) }
    end
    describe package("selinux") do
      it { should_not be_installed }
    end
  end
end

control "cis benchmark 1.6.1.2_Ensure_the_SELinux_state_is_enforcing" do
  title "Ensure the SELinux state is enforcing"
  desc  "Set SELinux to enable when the system is booted.\n\nRationale: SELinux must be enabled at boot time in to ensure that the controls it provides are in effect at all times."
  impact 1.0
  describe.one do
    describe file("/etc/selinux/config") do
      its("content") { should match(/^\s*SELINUX\s*=\s*enforcing\s*(\s+#.*)?$/) }
    end
    a = command("sestatus").stdout.scan(/.+/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/^SELinux status:\s+enabled$/) }
      end
    end
    a = command("sestatus").stdout.scan(/.+/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/^Current mode:\s+enforcing$/) }
      end
    end
    a = command("sestatus").stdout.scan(/.+/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/^Mode from config file:\s+enforcing$/) }
      end
    end
    describe package("selinux") do
      it { should_not be_installed }
    end
  end
end

control "cis benchmark 1.6.1.3_Ensure_SELinux_policy_is_configured" do
  title "Ensure SELinux policy is configured"
  desc  "Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.\n\nRationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that at least the default recommendations are met."
  impact 1.0
  describe.one do
    describe file("/etc/selinux/config") do
      its("content") { should match(/^\s*SELINUXTYPE\s*=\s*(ubuntu|default|mls)\s*(\s+#.*)?$/) }
    end
    a = command("sestatus").stdout.scan(/.+/)
    describe a do
      its("length") { should be > 0 }
    end
    a.each do |entry|
      describe entry do
        it { should match(/^Policy from config file:\s+(ubuntu|default|mls)$/) }
      end
    end
    describe package("selinux") do
      it { should_not be_installed }
    end
  end
end

control "cis benchmark 1.6.1.4_Ensure_no_unconfined_daemons_exist" do
  title "Ensure no unconfined daemons exist"
  desc  "Daemons that are not defined in SELinux policy will inherit the security context of their parent process.\n\nRationale: Since daemons are launched and descend from the init process, they will inherit the security context label initrc_t. This could cause the unintended consequence of giving the process more permission than it requires."
  impact 1.0
  describe.one do
    processes(/.*/).where { pid > 0 }.entries.each do |entry|
      describe entry.label.to_s.split(":")[2] do
        it { should_not cmp "initrc_t" }
      end
    end
    describe package("selinux") do
      it { should_not be_installed }
    end
  end
end

control "cis benchmark 1.6.2.1_Ensure_AppArmor_is_not_disabled_in_bootloader_configuration" do
  title "Ensure AppArmor is not disabled in bootloader configuration"
  desc  "Configure AppArmor to be enabled at boot time and verify that it has not been overwritten by the bootloader boot parameters.\n\nRationale: AppArmor must be enabled at boot time in your bootloader configuration to ensure that the controls it provides are not overridden."
  impact 1.0
  describe.one do
    describe file("/boot/grub/grub.cfg") do
      its("content") { should_not match(/^\s*linux\S*(\s+\S+)+\s+apparmor=0/) }
    end
    describe package("apparmor") do
      it { should_not be_installed }
    end
  end
end

control "cis benchmark 1.6.2.2_Ensure_all_AppArmor_Profiles_are_enforcing" do
  title "Ensure all AppArmor Profiles are enforcing"
  desc  "AppArmor profiles define what resources applications are able to access.\n\nRationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies that exist on the system are activated."
  impact 1.0
  describe.one do
    describe command("apparmor_status --profiled") do
      its("stdout") { should cmp > 0 }
    end
    describe command("apparmor_status --complaining") do
      its("stdout") { should cmp == 0 }
    end
    describe command("apparmor_status").stdout.scan(/^(\d+).*unconfined/).flatten do
      it { should cmp == 0 }
    end
    describe package("apparmor") do
      it { should_not be_installed }
    end
  end
end

control "cis benchmark 1.6.3_Ensure_SELinux_or_AppArmor_are_installed" do
  title "Ensure SELinux or AppArmor are installed"
  desc  "SELinux and AppArmor provide Mandatory Access Controls.\n\nRationale: Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available."
  impact 0.0
  describe.one do
    describe package("selinux") do
      it { should be_installed }
    end
    describe package("apparmor") do
      it { should be_installed }
    end
  end
end

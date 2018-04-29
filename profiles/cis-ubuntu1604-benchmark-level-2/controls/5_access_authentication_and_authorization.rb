# Controls mapped to CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0 12-28-2017
#
# Level 2 controls

control "cis benchmark 5.5_Ensure_root_login_is_restricted_to_system_console" do
  title "Ensure root login is restricted to system console"
  desc  "The file /etc/securetty contains a list of valid terminals that may be logged in directly as root.\n\nRationale: Since the system console has special properties to handle emergency situations, it is important to ensure that the console is in a physically secure location and that unauthorized consoles have not been defined."
  impact 0.0

  describe 'Compensating Control' do
    skip 'Compensating Control: AWS provides no console access'
  end
end

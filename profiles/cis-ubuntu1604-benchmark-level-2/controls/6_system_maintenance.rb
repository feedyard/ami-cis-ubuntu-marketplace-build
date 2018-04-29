# Controls mapped to CIS Ubuntu Linux 16.04 LTS Benchmark v1.1.0 12-28-2017
#
# Level 2 controls

control "cis benchmark 6.1.1_Audit_system_file_permissions" do
  title "Audit system file permissions"
  desc  "The Debian package manager has a number of useful options. One of these, the --verify option, can be used to verify that system packages are correctly installed. The --verify option can be used to verify a particular package or to verify all system packages. If no output is returned, the package is installed correctly. The following table describes the meaning of output from the verify option: Code MeaningS File size differs.M File mode differs (includes permissions and file type).5 The MD5 checksum differs.D The major and minor version numbers differ on a device file.L A mismatch occurs in a link.U The file ownership differs.G The file group owner differs.T The file time (mtime) differs. The dpkg -S command can be used to determine which package a particular file belongs to. For example the following commands determines which package the /bin/bash file belongs to:\n                # dpkg -S /bin/bashbash: /bin/bash\n                To verify the settings for the package that controls the /bin/bash file, run the following: # dpkg --verify bash??5?????? c /etc/bash.bashrc\n\nRationale: It is important to confirm that packaged system files and directories are maintained with the permissions they were intended to have from the OS vendor."
  impact 0.0

  describe 'Compensating Control' do
    skip 'Compensating Control: Use of CIS Marketplace provided images with validated'
  end
end
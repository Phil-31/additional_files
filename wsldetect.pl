package wsldetect;
use strict;
use warnings;

my %config = (hive          => "Software",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20220220);

sub getConfig{return %config}
sub getShortDescr {
	return "Detector Plugin for WSL2 on Win10";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}
my $VERSION = getVersion();
my @global_subkey;
my @distrolist;

sub pluginmain {
	my $class = shift; # get first argument
	my $hive = shift; # get second argument
	::logMsg("Launching wsldetect v.".$VERSION);
	::rptMsg("wsldetect v.".$VERSION); # banner
    ::rptMsg("(".$config{hive}.") ".getShortDescr()."\n"); # banner
	my $reg = Parse::Win32Registry->new($hive); # Load registry hive
	my $root_key = $reg->get_root_key; 
	my $kernel_version;
	my $kernel_installdate;
	my $indicator_counter = 0;
	my $apppath_counter = 0;
	my $sw_package_counter = 0;

#####################################################
	#SOFTWARE: get wsl kernel version
	::rptMsg("=============\nSOFTWARE: get wsl kernel version:");
	@global_subkey = ("Microsoft\\Windows\\CurrentVersion\\Lxss"); 
	::rptMsg("Registry path: Microsoft\\Windows\\CurrentVersion\\Lxss");
	
	if (my $key_path = $global_subkey[0]){# $key_path = Microsoft\\Windows\\CurrentVersion\\Lxss
		my $key;
		if ($key = $root_key->get_subkey($key_path)) {
			#::rptMsg("Registry path: ".$key_path);
			#::rptMsg($key->get_name);
			$kernel_version = $key->get_value("KernelVersion")->get_data();
			::rptMsg($key->get_value("KernelVersion")->get_name().": ".$kernel_version);
		}
		else {
			::rptMsg($key_path." not found.");
		}
	}
#####################################################
	#SOFTWARE: get installer of the Linux kernel	
	::rptMsg("=============\nSOFTWARE: get installer of the Linux kernel:");
	@global_subkey = ("Microsoft\\Windows\\CurrentVersion\\Installer\\UserData");
	::rptMsg("Registry path: Microsoft\\Windows\\CurrentVersion\\Installer\\UserData");

	if (my $key_path = $global_subkey[0]){ # $key_path = Microsoft\\Windows\\CurrentVersion\\Installer\\UserData
		my $key;
		if ($key = $root_key->get_subkey($key_path)) { 
			my @subkeys = $key->get_list_of_subkeys(); # @subkeys = Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\* > Sids of users
			foreach my $subk (@subkeys) { # get through all users
				#::rptMsg("Key name: ".$subk->get_name());
				my @products = $subk->get_subkey("Products")->get_list_of_subkeys(); 
				foreach my $s (@products) { # get through all Products of all users
					#::rptMsg($s->get_name());
					#::rptMsg($s->get_subkey("InstallProperties")->get_value("DisplayName")->get_data());
					if($s->get_subkey("InstallProperties")->get_value("DisplayName")->get_data() =~ m/Linux/g){ # get the Linux Kernel Installer
						my @naming;
						$naming[0] = $s->get_name;
						$naming[1] = $s->get_subkey("InstallProperties")->get_value("DisplayName")->get_data();
						$naming[2] = $s->get_subkey("InstallProperties")->get_value("Publisher")->get_data();
						$naming[3] = $s->get_subkey("InstallProperties")->get_value("DisplayVersion")->get_data();
						$naming[4] = $s->get_subkey("InstallProperties")->get_value("InstallDate")->get_data();
						$kernel_installdate = $s->get_subkey("InstallProperties")->get_value("InstallDate")->get_data();
						::rptMsg("Installer Name: ".$naming[1]." by "."$naming[2]");
						::rptMsg(" Installer ID: ".$naming[0]);
						::rptMsg(" Version: ".$naming[3]);
						::rptMsg(" Installed on: ".$naming[4]);
					}
					else{
						next;
					}
				}
			}
		}
		else {
			::rptMsg($key_path." not found.");
		}
	}
	
#####################################################	
	#SOFTWARE: get distro in appaths
	::rptMsg("=============\nSOFTWARE: get distro in appaths:");
	@global_subkey = get_all_subkeys_from_path($root_key,"Microsoft\\Windows\\CurrentVersion\\App Paths");
	::rptMsg("Registry path: Microsoft\\Windows\\CurrentVersion\\App Paths");
	
	foreach my $subk (@global_subkey){ # $subk = Microsoft\\Windows\\CurrentVersion\\App Paths\\*
		#::rptMsg("Keyname: ".$subk->get_name());
		if (find_distro_in_string($subk->get_name()) == 1){ # get the Linux Distro App Path
			$indicator_counter += 1;
			$apppath_counter += 1;
			push(@distrolist, $subk->get_name());
			::rptMsg("Key name: ".$subk->get_name());
			::rptMsg(" Key value: ".$subk->get_value("")->get_data());
			::rptMsg(" Last modified: ". ::getDateFromEpoch($subk->get_timestamp()));
		}
	}
#####################################################	
	# SOFTWARE: get distro in software packages
	::rptMsg("=============\nSOFTWARE: get distro in software packages:");
	@global_subkey = get_all_subkeys_from_path($root_key,"Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\PackageRepository\\Packages");
	::rptMsg("Registry path: Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\PackageRepository\\Packages");

	foreach my $subk (@global_subkey){ # $subk = Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\PackageRepository\\Packages\\*
		# ::rptMsg("Keyname: ".$subk->get_name());
		if (find_distro_in_string($subk->get_name()) == 1){ # get the Linux Distro Software Package
			$indicator_counter += 1;
			$sw_package_counter += 1;
			::rptMsg("Keyname: ".$subk->get_name());
			eval { # only print data if there is any
				::rptMsg(" Key value: ".$subk->get_value("Path")->get_data());
			};
			::rptMsg(" Last modified: ". ::getDateFromEpoch($subk->get_timestamp()));
		}
	}
#####################################################
	# print summary
	::rptMsg("=====================================");
	::rptMsg("Result Summary: \n---------------");
	::rptMsg("Kernel Version: ".$kernel_version);
	::rptMsg("Kernel Install Date: ".$kernel_installdate);
	::rptMsg("Indicators in Appaths: ".$apppath_counter);
	::rptMsg("Indicators in Software Packages: ".$sw_package_counter);
	::rptMsg("-------------------------------------");
	::rptMsg("Total Indicators of WSL: ".$indicator_counter);
	::rptMsg("-------------------------------------");
	::rptMsg("Following WSL Distros were detected:");
	foreach my $distro (@distrolist){
		::rptMsg("   ".$distro);
	}
}

#####################################################
# sub functions
sub get_all_subkeys_from_path {
	my $root_key = shift;
	my $path = shift;
	my $key;
	my @sub_keys;
	
	if ($key = $root_key->get_subkey($path)){
		@sub_keys = $key->get_list_of_subkeys();
	}
	else {
		::rptMsg($path."not found");
	}	
	return @sub_keys;
}

sub find_distro_in_string {
	my $inputtext = shift;
	# ::rptMsg("inputtext is: ".$inputtext);
	if ($inputtext =~ m/debian|Debian|ubuntu|Ubuntu|kali|Kali|opensuse|openSUSE|sles|SLES|suselinuxenterprise|SUSELinuxEnterprise/g){
		#::rptMsg("A distro was found in: ".$inputtext);
		return 1;
	}
	else{
		return 0;
	}
}
1;

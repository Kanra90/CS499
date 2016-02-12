package Identity::AD;

our $VERSION = 1.0;

use strict;
use warnings; no warnings qw(uninitialized);

use Net::LDAPS ();
use Net::LDAP::Entry ();
use POSIX ();
use Time::ParseDate ();
use Identity ();

my $DOMAIN      = 'cpp.edu';
my $WINDOMAIN   = "ad.$DOMAIN";
my @CONTROLLERS = ('itdc01', 'itdc02', 'itdc03', 'itdc04', 'itdc05', 'itdc06');
my $BASE        = 'dc=' . join(',dc=', split(/\./, $WINDOMAIN));
my $DN          = 'cn';
my $MAX_RETRIES = 3;
my $RETRY_SLEEP = 2;

#####################################
# Disable read (r) and/or write (w) #
#####################################

my $disable;

sub disable {

	($disable) = @_;
}

################################
# Open directory (ldap) handle #
################################

my $ldap;
my $ldap_dc;
my $lockoutduration;

sub _directory {

	if (! $ldap) {

		foreach my $controller (@CONTROLLERS) {
			if ($ldap = Net::LDAPS->new("$controller.$WINDOMAIN", timeout => 10,
						    raw => qr/(?i:^jpegPhoto|;binary)/)) {
				$ldap_dc = $controller;
				last;
			}
		}
		$ldap or
			return Identity::log("error opening directory: $@");

		open(PASSWORD, '/etc/security/secrets/cppad-idmgmt') or
			return Identity::log('error: ldap login unauthorized');

		my $password = <PASSWORD>;
		close(PASSWORD);
		chop($password);

		my $status = $ldap->bind(
			"$DN=it_svc_idmgmt,OU=service,$BASE",
			password => $password,
		); $status->code() and do {
			$ldap_dc = undef;
			return Identity::log('error binding to directory: ' . $status->error());
			};

		my $search = $ldap->search(
			scope  => 'base',
			base   => "$BASE",
			filter => "(objectclass=*)",
			attrs  => [ 'lockoutDuration' ]
		);

		if ($search->code()) {
			Identity::log("warning: failed to lookup base object: "
				. $search->error() . ' (' . $search->code() . ')');
		}
		elsif (defined(my $entry = $search->shift_entry())) {
			$lockoutduration = $entry->get_value('lockoutDuration');
			$lockoutduration = -($lockoutduration/10000000);
		}
		else {
			Identity::log('warning: base object search returned no entries');
		}
	}
	return $ldap;
}

##############################
# Search for directory entry #
##############################

my $ATTRS = [
	'accountExpires',
	'department',
	'description',
	'displayName',
	'extensionAttribute12',
	'facsimileTelephoneNumber',
	'givenName',
	'homeDirectory',
	'initials',
	'lockoutTime',
	'mail',
	'mailNickname',
	'physicalDeliveryOfficeName',
	'proxyAddresses',
	'pwdLastSet',
	'sn',
	'targetAddress',
	'telephoneNumber',
	'title',
	'userAccountControl',
	'whenCreated',
	'calstateEduPersonEmplid',
	'calstateEduPersonRestrictFlag',
	'cppEduPersonAffiliation',
	'cppGroupRestrictFlag',
	'cppGroupPopulation',
];

my %ldap_retry_errors = (
	0x01 => 1,
	0x33 => 1,
	0x34 => 1,
	0x50 => 1,
	0x51 => 1,
	0x52 => 1,
	0x55 => 1,
	0x5b => 1,
);

sub _entry {

	my ($entity, $attrs, $ou) = @_;

	my $name = $entity->{name};
	my $type = $entity->{'-type'};
	$ou ||= $type;

	my $entry;
	$entry = $entity->{"-ad_${ou}_entry"} unless ref($attrs);

	if (! $entry) {
		$ldap = _directory(); ref($ldap) or return $ldap;

		my $search = $ldap->search(
			scope  => 'sub',
			base   => "OU=$ou,$BASE",
			filter => "($DN=$name" . ($ou eq 'groupmail' && '-mbx') . ')',
			attrs  => ref($attrs) ? $attrs : $ATTRS,
		);

		if ($search->code() && defined($ldap_retry_errors{$search->code()})) {
			$ldap = $ldap_dc = undef; $ldap = _directory(); ref($ldap) or return $ldap;

			$search = $ldap->search(
				scope  => 'sub',
				base   => "OU=$ou,$BASE",
				filter => "($DN=$name" . ($ou eq 'groupmail' && '-mbx') . ')',
				attrs  => ref($attrs) ? $attrs : $ATTRS,
			);
		}
		$search->code() and
			return Identity::log("error getting $ou $name entry: " . $search->error() . ' (' . $search->code() . ')');

		$entry = $search->shift_entry() or
			return "$name is not an existing $ou";

		$entity->{"-ad_${ou}_entry"} = $entry unless ref($attrs);
	}
	return $entry;
}

sub _update {

	my ($entry) = @_;

	my $status;
	my $try = 1;

	while(1) {
		$ldap = _directory(); ref($ldap) or return $ldap;

		$status = $entry->update($ldap);

		last unless ($status->code() && defined($ldap_retry_errors{$status->code()}));

		$ldap = undef; last unless ($try < $MAX_RETRIES);

		Identity::log("warning: retryable update failure " . $status->error() . ' (' . $status->code() . ')');

		sleep($try * $RETRY_SLEEP); $try++;
	};

	return ($status->code() ? $status->error() . ' (' . $status->code() . ')' : undef);
}

########################
# Create user or group #
########################

sub create {

	my ($entity) = @_;

	my $name     = $entity->{name};
	my $type     = $entity->{'-type'};
	my $title    = $entity->{title};
	my $phone    = $entity->{phone};
	my $fax      = $entity->{fax};
	my $location = $entity->{location};

	my $entry = Net::LDAP::Entry->new();

	$entry->dn("$DN=$name,ou=$type,$BASE");

	$entry->add(displayName => $title);
	if ($type eq 'user') {

		my $last_name  = $entity->{last_name};
		my $first_name = $entity->{first_name};
		my $mi         = $entity->{mi};
		my $position   = $entity->{position};
		my $emplid     = $entity->{emplid};
		my $ferpa      = $entity->{ferpa};

		($first_name, $mi) = $first_name =~ /\.$/ ? ($mi, undef) : ($first_name, substr($mi, 0, 1) . '.') if length($mi) > 6;

		$entry->add(
			objectClass        => ['top','person','organizationalPerson','user'],
			$DN                => $name,
			sn                 => $last_name,
			mail               => "$name\@$DOMAIN",
			wWWHomePage        => "http://www.$DOMAIN/~$name/",
			homeDirectory      => "\\\\files.$DOMAIN\\user\\$name",
			homeDrive	   => 'Z:',
			sAMAccountName     => $name,
			userPrincipalName  => "$name\@$DOMAIN",
			unicodePwd         => [ join("\0", split(//, "\"$entity->{password}\"")) . "\0" ],
			userAccountControl => '546',
			accountExpires     => 0,
		);
		$entry->add(givenName => $first_name)    if $first_name;
		$entry->add(initials  => $mi)            if $mi;
		$entry->add(title     => $position->[0]) if $position;
		$entry->add(calstateEduPersonEmplid       => $emplid)     if $emplid;
		$entry->add(calstateEduPersonRestrictFlag => $ferpa)      if $ferpa;
	}
	else {
		my $visibility = $entity->{visibility} || 'public';
		my $population = $entity->{population};

		$entry->add(
			objectClass    => ['top', 'group'],
			sAMAccountName => $name,
			description    => $title,
			cppGroupPopulation => $population, 
			# Universal security group, hardcoded constants woo woo
			groupType => '-2147483640',
		);
		$entry->add(cppGroupRestrictFlag => 'member') if $visibility eq 'private';
	}
	$entry->add(telephoneNumber            => $phone->[0])    if $phone;
	$entry->add(facsimileTelephoneNumber   => $fax->[0])      if $fax;
	$entry->add(physicalDeliveryOfficeName => $location->[0]) if $location;

	return if $disable =~ /r/;

	$ldap = _directory(); ref($ldap) or return $ldap;

	return if $disable =~ /w/;

	my $status = _update($entry); $status and
		return Identity::log("error adding $type $name to directory: $status");

	$entity->{'-ad_entry'} = $entry;

	return;
}

########################
# Delete user or group #
########################

sub delete {

	my ($entity) = @_;

	my $name = $entity->{name};
	my $type = $entity->{'-type'};

	return if $disable =~ /r/;

	my $entry           = _entry($entity); ref($entry) or return $entry;
	my $groupmail_entry = $type eq 'group' && _entry($entity, undef, 'groupmail');

	return if $disable =~ /w/;

	$entry->delete();

	my $status = _update($entry); $status and
		return Identity::log("error deleting $type $name: $status");

	if (ref($groupmail_entry)) {
		$groupmail_entry->delete();

		$status = _update($groupmail_entry) and
			return Identity::log("error deleting $type $name mailbox: $status");
	}
	
	return;
}

#########################
# Store user department #
#########################

sub department {

	my ($user, $new_department) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $department = $entry->get_value('department', asref => 1);

	if ($new_department and ($department xor @$new_department) || $department->[0] ne $new_department->[0]) {

		my $name = $user->{name};

		Identity::log("store user $name department $new_department->[0] (was " . ($department && $department->[0]) . ')');

		$entry->replace(department => @$new_department ? $new_department->[0] : []);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name department: $status");
	}
	return;
}

#######################
# Store user disabled #
#######################

sub disabled {

	my ($user, $new_disabled) = @_;

	if (defined($new_disabled)) {

		return if $disable =~ /r/;

		my $entry = _entry($user); ref($entry) or return $entry;

		my $control = $entry->get_value('userAccountControl');

		$entry->replace(userAccountControl => $new_disabled ? $control | 0x02 : $control & ~0x02);

		my $name = $user->{name};

		$new_disabled = $new_disabled ? 'T' : 'F';

		Identity::log("store user $name disabled $new_disabled");

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name disabled: $status");
	}
	return;
}

######################################
# Fetch date of last password change #
######################################

sub pwd_lastchange {

	my ($user) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $pwd_lastchange = $entry->get_value('pwdLastSet');

	$pwd_lastchange or
		return 'no password change attribute found';

	$pwd_lastchange =~ s/\d{7}$//;
	$pwd_lastchange -= 134774 * 24 * 60 * 60;
	$user->{pwd_lastchange} = $pwd_lastchange;

	return;
}

#########################################
# Store or fetch account lockout status #
#########################################
sub lockout {

	my ($user, $unlock) = @_;

	my $name = $user->{name};

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $lockout_time = $entry->get_value('lockoutTime');

	# No lockout time, not locked out, no need to unlock
	$lockout_time or return;

	$lockout_time =~ s/\d{7}$//;
	$lockout_time -= 134774 * 24 * 60 * 60;

	# lockout already expired, not locked out, no need to unlock
	($lockout_time + $lockoutduration > time()) or return;

	if ($unlock) {
		Identity::log("store user $name lockout false");

		$entry->replace(lockoutTime => 0);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name lockout: $status");

	}
	else {
		push(@{$user->{lockout}}, { name => 'ad',
					    time => $lockout_time,
					    duration => $lockoutduration });
	}

	return;
}

#############################
# Store password expiration #
#############################

sub pwd_expired {

	my ($user, $new_pwd_expired) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;
	my $name = $user->{name};

	my $pwd_expired = ($entry->get_value('pwdLastSet') == 0) ? 'T' : 'F';

	if (defined($new_pwd_expired)) {
		$new_pwd_expired = $new_pwd_expired =~ /^[Tt1]$/ ? 'T' : 'F';

		if ($new_pwd_expired ne $pwd_expired) {
			$entry->replace(pwdLastSet => ($new_pwd_expired eq 'T' ? 0 : -1));

			Identity::log("store user $name pwd_expired $new_pwd_expired (was $pwd_expired)");

			return if $disable =~ /w/;

			my $status = _update($entry); $status and
				return Identity::log("error storing user $name pwd_expired: $status");
		}	
	}

	return;
}

#########################
# Store user expiration #
#########################

sub expiration {

	my ($user, $new_expiration) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $expiration = $entry->get_value('accountExpires') || 0;
	if ($expiration) {
		$expiration =~ s/\d{7}$//;
		$expiration -= 134774 * 24 * 60 * 60;
	}

	if (defined($new_expiration) && $new_expiration != $expiration) {

		$entry->replace(accountExpires => $new_expiration && ($new_expiration + (134774 * 24 * 60 * 60)) . '0000000');

		my $name = $user->{name};

		Identity::log(
			"store user $name expiration " . ($new_expiration && POSIX::strftime('%Y-%m-%d %T', localtime($new_expiration))) .
			' (was ' . ($expiration && POSIX::strftime('%Y-%m-%d %T', localtime($expiration))) . ')'
		);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name expiration: $status");
	}
	return;
}

###########################
# Store user or group fax #
###########################

sub fax {

	my ($entity, $new_fax) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($entity); ref($entry) or return $entry;

	my $fax = $entry->get_value('facsimileTelephoneNumber', asref => 1);

	if ($new_fax and ($fax xor @$new_fax) || $fax->[0] ne $new_fax->[0]) {

		my $name = $entity->{name};
		my $type = $entity->{'-type'};

		Identity::log("store $type $name fax $new_fax->[0] (was " . ($fax && $fax->[0]) . ')');

		$entry->replace(facsimileTelephoneNumber => @$new_fax ? $new_fax->[0] : []);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing $type $name fax: $status");
	}
	return;
}

#########################################
# Store or fetch user homedir (Windows) #
#########################################

sub homedir {

	my ($user, $new_homedir) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $homedir = $entry->get_value('homeDirectory');

	my $name = $user->{name};

	if ($new_homedir) {
		if ($new_homedir eq 'winfile') {
			$new_homedir = "\\\\files.win.$DOMAIN\\user\\$name";
		}
		elsif ($new_homedir eq 'zfs') {
			$new_homedir = "\\\\files.$DOMAIN\\user\\$name";
		}
		elsif ($new_homedir eq 'zfsraw') {
			my $status = $user->zfs_server(); $status and
				return "error: failed to lookup backend zfs server - $status";
				
			$new_homedir = "\\\\$user->{zfs_server}\\$name";
		}
		else {
			return Identity::log("error: invalid homedir $new_homedir");
		}
	}

	if ($new_homedir and $homedir ne $new_homedir) {

		$entry->replace(homeDirectory => $new_homedir);

		Identity::log("store user $name homedir $new_homedir (was $homedir)");

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name homedir: $status");

		$homedir = $new_homedir;
	}
	$user->{homedir} = $homedir if defined($homedir);
	return;
}

################################
# Store user or group location #
################################

sub location {

	my ($entity, $new_location) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($entity); ref($entry) or return $entry;

	my $location = $entry->get_value('physicalDeliveryOfficeName', asref => 1);

	if ($new_location and ($location xor @$new_location) || $location->[0] ne $new_location->[0]) {

		my $name = $entity->{name};
		my $type = $entity->{'-type'};

		Identity::log("store $type $name location $new_location->[0] (was " . ($location && $location->[0]) . ')');

		$entry->replace(physicalDeliveryOfficeName => @$new_location ? $new_location->[0] : []);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing $type $name location: $status");
	}
	return;
}

########################
# Update group members #
########################

sub members {

	my ($group, $update_members) = @_;

	my $name     = $group->{name};
	my $populate = $update_members->{populate};
	my $remove   = $update_members->{remove};
	my $add      = $update_members->{add};

	return if $disable =~ /r/;

	my $entry = _entry($group); ref($entry) or return $entry;

	my %members;
	my @range;
	my $first = 0;

	while (1) {
		$range[0] = "member;range=$first-*";

		my $entry = _entry($group, \@range); $entry or return $entry;

		my $attributes = $entry->get_value('member', alloptions => 1); $attributes or
			last;

		my ($option, $values) = each(%$attributes);

		foreach (@$values) {
			/^$DN=([^,]*)/i;
			$members{$1} = 1;
		}
		last if $option !~ /^;range=(\d+)-(.+)$/i || $2 eq '*';
		$first = $2 + 1;
	}

	if ($populate) {
		my (@remove, @add);

		foreach my $username (keys(%members)) {
			push(@remove, $username) unless $populate->{$username};
		}
		foreach my $username (keys(%$populate)) {
			push(@add, $username) unless $members{$username};
		}
		($remove, $add) = (\@remove, \@add);
	}
	my $error;

	if ($remove) {
		my @remove_dn;

		foreach my $username (@$remove) {

			next unless $members{$username};
			push(@remove_dn, "$DN=$username,ou=user,$BASE");
			delete($members{$username});
		}
		if (@remove_dn) {{

			Identity::log("store group $name members -" . @remove_dn);

			last if $disable =~ /w/;

			# Temporary kludge to work around broken SSL large updates
			for (my $i = 0; $i < @remove_dn; $i+=100) {
				my @remove_dn_subset = @remove_dn[$i..($i+99 < @remove_dn ? $i+99 : @remove_dn - 1)];
				$entry->delete(member => \@remove_dn_subset);
				my $status = _update($entry); $status and
					$error .= Identity::log("error removing users from group $name: $status");
			}
		}}
	}
	if ($add) {
		my @add_dn;

		foreach my $username (@$add) {

			next if $members{$username};
			$error .= Identity::log("error adding user $username to group $name: user doesn't exist") and
				next if Identity::type($username) ne 'user';
			push(@add_dn, "$DN=$username,ou=user,$BASE");
			$members{$username} = 1;
		}
		if (@add_dn) {{

			Identity::log("store group $name members +" . @add_dn);

			last if $disable =~ /w/;

			# Temporary kludge to work around broken SSL large updates
			for (my $i = 0; $i < @add_dn; $i+=100) {
				my @add_dn_subset = @add_dn[$i..($i+99 < @add_dn ? $i+99 : @add_dn - 1)];
				$entry->add(member => \@add_dn_subset);
				my $status = _update($entry); $status and
					$error .= Identity::log("error adding users to group $name: $status");
			}
		}}
	}
	return $error;
}

###############################
# Store username or groupname #
###############################

sub name {

	my ($entity, $new_name) = @_;

	my $name = $entity->{name};
	my $type = $entity->{'-type'};

	return if $disable =~ /r/;

	my $entry           = _entry($entity); ref($entry) or return $entry;
	my $groupmail_entry = $type eq 'group' && _entry($entity, undef, 'groupmail');
	my $error;

	$entry->replace(
			sAMAccountName    => $new_name,
	);
	if ($entry->exists('mail')) {
		$entry->replace(mail => "$new_name\@" . ($type eq 'group' && 'groups.') . $DOMAIN);
	}
	if ($entry->exists('mailNickname')) {
		$entry->replace(mailNickname => $new_name);
	}
	if ($entry->exists('proxyAddresses')) {
		foreach my $value ($entry->get_value('proxyAddresses')) {
			if ($value =~ /^smtp:$name@/i) {
				my $new_value = $value;
				$new_value =~ s/:$name@/:$new_name@/;
				$entry->delete(proxyAddresses => [ $value ]);
				$entry->add(proxyAddresses => $new_value );
			}
		}
	}

	if ($type eq 'user') {
		my $home_directory = $entry->get_value('homeDirectory');
		$home_directory =~ s/$name$/$new_name/;
		
		$entry->replace(
				homeDirectory     => $home_directory,
				userPrincipalName => "$new_name\@$DOMAIN",
			        wWWHomePage       => "http://www.$DOMAIN/~$new_name/",
				);
		
		if ($entry->exists('targetAddress')) {
			$entry->replace(targetAddress => "SMTP:$new_name\@livecsupomona.mail.onmicrosoft.com");
		}
	}

	if (ref($groupmail_entry)) {
		$groupmail_entry->replace(
				mail              => "$new_name\@$DOMAIN",
				mailNickname      => "${new_name}-mbx",
				sAMAccountName    => "${new_name}-mbx",
				userPrincipalName => "${new_name}-mbx\@$DOMAIN",
				targetAddress => "SMTP:$new_name\@livecsupomona.mail.onmicrosoft.com",
				);

		foreach my $value ($groupmail_entry->get_value('proxyAddresses')) {
		Identity::log("Found proxy address $value");
			if ($value =~ /^smtp:$name@/i) {
				my $new_value = $value;
				$new_value =~ s/:$name@/:$new_name@/;
				$groupmail_entry->delete(proxyAddresses => [ $value ]);
				$groupmail_entry->add(proxyAddresses => $new_value );
			}
			elsif ($value =~ /^smtp:${name}-mbx@/i) {
				my $new_value = $value;
				$new_value =~ s/:${name}-mbx@/:${new_name}-mbx@/;
				$groupmail_entry->delete(proxyAddresses => [ $value ]);
				$groupmail_entry->add(proxyAddresses => $new_value );
			}
		}
	}
		
	return if $disable =~ /w/;

	my $status = _update($entry); $status and
		$error .= Identity::log("error renaming $type $name to $new_name: $status");

	$status = $ldap->moddn($entry->dn(),
		newrdn       => "$DN=$new_name",
		deleteoldrdn => 1,
	); $status->code() and
		$error .= Identity::log("error renaming $type $name DN to $new_name: " . $status->error());

	delete($entity->{"-ad_${type}_entry"});

	if (ref($groupmail_entry)) {
	
		my $status = _update($groupmail_entry); $status and
		$error .= Identity::log("error renaming $type $name mailbox to $new_name: $status");

		$status = $ldap->moddn($groupmail_entry->dn(),
			newrdn       => "$DN=${new_name}-mbx",
			deleteoldrdn => 1,
		); $status->code() and
			$error .= Identity::log("error renaming $type $name mailbox DN to $new_name: " . $status->error());

		delete($entity->{"-ad_groupmail_entry"});
	}

	return $error;
}

#######################
# Store user password #
#######################

sub password {

	my ($user, $new_password) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	$entry->replace('unicodePwd' => [ join("\0", split(//, "\"$new_password\"")) . "\0" ]);

	my $name = $user->{name};

	Identity::log("store user $name password");

	return if $disable =~ /w/;

	my $status = _update($entry); $status and
		return Identity::log("error storing user $name password: $status");

	return;
}

#############################
# Store user or group phone #
#############################

sub phone {

	my ($entity, $new_phone) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($entity); ref($entry) or return $entry;

	my $phone = $entry->get_value('telephoneNumber', asref => 1);

	if ($new_phone and ($phone xor @$new_phone) || $phone->[0] ne $new_phone->[0]) {

		my $name = $entity->{name};
		my $type = $entity->{'-type'};

		Identity::log("store $type $name phone $new_phone->[0] (was " . ($phone && $phone->[0]) . ')');

		$entry->replace(telephoneNumber => @$new_phone ? $new_phone->[0] : []);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing $type $name phone: $status");
	}
	return;
}

#######################
# Store user position #
#######################

sub position {

	my ($user, $new_position) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $position = $entry->get_value('title', asref => 1);

	if ($new_position and ($position xor @$new_position) || $position->[0] ne $new_position->[0]) {

		my $name = $user->{name};

		Identity::log("store user $name position $new_position->[0] (was " . ($position && $position->[0]) . ')');

		$entry->replace(title => @$new_position ? $new_position->[0] : []);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name position: $status");
	}
	return;
}

#################
# Store user mi #
#################

sub mi {

	my ($user, $new_mi) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $mi = $entry->get_value('initials');

	if ($new_mi && $new_mi ne $mi) {

		my $name = $user->{name};

		Identity::log("store user $name mi $new_mi (was $mi)");

		$entry->replace(initials => $new_mi);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name mi: $status");
	}
	return;
}

#########################
# Store user first_name #
#########################

sub first_name {

	my ($user, $new_first_name) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $first_name = $entry->get_value('givenName');

	if ($new_first_name && $new_first_name ne $first_name) {

		my $name = $user->{name};

		Identity::log("store user $name first_name $new_first_name (was $first_name)");

		$entry->replace(givenName => $new_first_name);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name first_name: $status");
	}
	return;
}

########################
# Store user last_name #
########################

sub last_name {

	my ($user, $new_last_name) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $last_name = $entry->get_value('sn');

	if ($new_last_name && $new_last_name ne $last_name) {

		my $name = $user->{name};

		Identity::log("store user $name last_name $new_last_name (was $last_name)");

		$entry->replace(sn => $new_last_name);

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name last_name: $status");
	}
	return;
}

#############################
# Store user or group title #
#############################

sub title {

	my ($entity, $new_title) = @_;

	my $name = $entity->{name};
	my $type = $entity->{'-type'};

	return if $disable =~ /r/;

	my $entry = _entry($entity); ref($entry) or return $entry;
	my $groupmail_entry = $type eq 'group' && _entry($entity, undef, 'groupmail');
	my $error;

	my $title = $entry->get_value($type eq 'user' ? 'displayName' : 'description');

	if ($new_title && $new_title ne $title) {

		$entry->replace(displayName => $new_title);

		Identity::log("store $type $name title $new_title (was $title)");

		if ($type eq 'group') {
			$entry->replace(description => $new_title);
		}
		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			$error .= Identity::log("error storing $type $name title: $status");

		if (ref($groupmail_entry)) {
			$groupmail_entry->replace(displayName => $new_title);

			$status = _update($groupmail_entry) and
				$error .= Identity::log("error storing $type $name mailbox title: $status");
		}
	}

	return $error;
}

##########################
# Store group visibility #
##########################

sub visibility {
	my ($group, $new_visibility) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($group); ref($entry) or return $entry;

	my $visibility = grep($_ eq 'member', $entry->get_value('cppGroupRestrictFlag')) ? 'private' : 'public';

	if ($new_visibility && $new_visibility ne $visibility) {

		my $name = $group->{name};

		if ($new_visibility eq 'private') {
			$entry->add(cppGroupRestrictFlag => 'member');
		}
		else {
			$entry->delete(cppGroupRestrictFlag => ['member']);
		}

		Identity::log("store group $name visibility $new_visibility (was $visibility)");

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing group $name visibility: " . $status);

		$visibility = $new_visibility;
	}

	$group->{visibility} = $visibility;

	return;
}


################################
# Fetch date of group creation #
################################

sub create_date {

	my ($group) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($group); ref($entry) or return $entry;

	my $create_date = $entry->get_value('whenCreated');

	$create_date or
		return 'no creation date attribute found';

	if ($create_date =~ /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/) {
		$group->{create_date} = $create_date =
			Time::ParseDate::parsedate("$1-$2-$3 ${4}:${5}:${6}");
	}
	else {
		return 'invalid date format';
	}

	return;
}

###################################
# Store or fetch user affiliation #
###################################

sub affiliation {

	my ($user, $new_affiliation) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $affiliation = $entry->get_value('cppEduPersonAffiliation', asref => 1);

	if (defined($new_affiliation)) {

		my $affiliation_string = defined($affiliation) && join(',', sort(@$affiliation));
		my $new_affiliation_string = defined($new_affiliation) && join(',', sort(@$new_affiliation));

		if ($new_affiliation_string ne $affiliation_string) {

			my $name = $user->{name};

			my @eduPersonAffiliation;
			my $eduPersonPrimaryAffiliation;

			foreach my $eduPersonAffiliation ('faculty', 'staff', 'employee', 'student', 'member', 'affiliate') {

				if (grep($_ eq $eduPersonAffiliation, @$new_affiliation)) {
					push(@eduPersonAffiliation, $eduPersonAffiliation);
					$eduPersonPrimaryAffiliation ||= $eduPersonAffiliation;
				}
			}
			$entry->replace(eduPersonAffiliation => \@eduPersonAffiliation);
			$entry->replace(eduPersonPrimaryAffiliation => $eduPersonPrimaryAffiliation);
			$entry->replace(cppEduPersonAffiliation => $new_affiliation);

			Identity::log("store user $name affiliation $new_affiliation_string (was $affiliation_string)");

			return if $disable =~ /w/;

			my $status = _update($entry); $status and
				return Identity::log("error storing user $name affiliation: " . $status);

			$affiliation = $new_affiliation;
		}
	}
	$user->{affiliation} = $affiliation if defined($affiliation);
	return;
}

#####################
# Store user emplid #
#####################

sub emplid {

	my ($user, $new_emplid) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $emplid = $entry->get_value('calstateEduPersonEmplid');

	if (defined($new_emplid) && $emplid ne $new_emplid) {

		my $name = $user->{name};

		if ($new_emplid ne '') {
			$entry->replace(calstateEduPersonEmplid => $new_emplid);
		}
		else {
			$entry->delete('calstateEduPersonEmplid');
		}

		Identity::log("store user $name emplid $new_emplid (was $emplid)");

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name emplid: " . $status);

	}
	return;
}

#############################
# Store or fetch user ferpa #
#############################

sub ferpa {

	my ($user, $new_ferpa) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;

	my $ferpa = $entry->get_value('calstateEduPersonRestrictFlag');

	if (defined($new_ferpa) && $ferpa ne $new_ferpa) {

		my $name = $user->{name};

		if ($new_ferpa ne '') {
			$entry->replace(calstateEduPersonRestrictFlag => $new_ferpa);
		}
		else {
			$entry->delete('calstateEduPersonRestrictFlag');
		}

		Identity::log("store user $name ferpa $new_ferpa (was $ferpa)");

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing user $name ferpa: " . $status);

		$ferpa = $new_ferpa;
	}
	$user->{ferpa} = $ferpa if defined($ferpa);
	return;
}

###################################
# Store or fetch group population #
###################################

sub population {

	my ($group, $new_population) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($group); ref($entry) or return $entry;

	my $population = $entry->get_value('cppGroupPopulation');

	if ($new_population && $new_population ne $population) {

		my $name = $group->{name};

		$entry->replace(cppGroupPopulation => $new_population);

		Identity::log("store group $name population $new_population (was $population)");

		return if $disable =~ /w/;

		my $status = _update($entry); $status and
			return Identity::log("error storing group $name population: " . $status);

		$population = $new_population;
	}

	$group->{population} = $population;
	return;
}

###############################
# Fetch user or group o365mbx #
###############################

sub o365mbx {

	my ($entity) = @_;

	return if $disable =~ /r/;

	my $entry = _entry($entity); ref($entry) or return $entry;

	my $o365mbx = $entry->get_value('extensionAttribute12');

	if ($o365mbx eq 'GOTMBX') {
		$entity->{o365mbx} = 'true';
	}

	return;
}

1;
__END__

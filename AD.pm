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

# Variables for _directory

my $ldap;
my $ldap_dc;
my $lockoutduration;

# _directory opens an LDAP directory handle.
# Parameters:
# None
# Returns:
# 1. String - If LDAP cannot be reached.
# 2. String - If the file containing the password cannot be read.
# 3. String - If the bind request failed.
# 4. Net::LDAPS - Otherwise, it returns the directory handle.

sub _directory
{
# Attempts to open a directory handle if there is not one already.
	if (!$ldap)
	{
# Finds the first working controller and opens a handle. They are assigned to $ldap_dc and $ldap. Otherwise returns an error.
		foreach my $controller (@CONTROLLERS)
		{
			if ($ldap = Net::LDAPS->new("$controller.$WINDOMAIN", timeout => 10, raw => qr/(?i:^jpegPhoto|;binary)/))
			{
				$ldap_dc = $controller;
				last;
			}
		}
		$ldap or return Identity::log("error opening directory: $@");
# Gets the password or returns an error.
		open(PASSWORD, '/etc/security/secrets/cppad-idmgmt') or return Identity::log('error: ldap login unauthorized');
		my $password = <PASSWORD>;
		close(PASSWORD);
		chop($password);
# Sends a bind request. Returns an error on fail.
		my $status = $ldap->bind("$DN=it_svc_idmgmt,OU=service,$BASE", password => $password,);
		$status->code() and do
		{
			$ldap_dc = undef;
			return Identity::log('error binding to directory: ' . $status->error());
		};
# Searches the directory for entries containing lockoutDuration. Logs an error if searching failed or there are no entries. Otherwise, gets the first lockoutDuration.
		my $search = $ldap->search(scope => 'base', base => "$BASE", filter => "(objectclass=*)", attrs  => [ 'lockoutDuration' ]);
		if ($search->code())
		{
			Identity::log("warning: failed to lookup base object: " . $search->error() . ' (' . $search->code() . ')');
		}
		elsif (defined(my $entry = $search->shift_entry()))
		{
			$lockoutduration = $entry->get_value('lockoutDuration');
			$lockoutduration = -($lockoutduration/10000000);
		}
		else
		{
			Identity::log('warning: base object search returned no entries');
		}
	}
	return $ldap;
}

# Variables for _entry
my $ATTRS =
[
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

my %ldap_retry_errors =
(
0x01 => 1,
0x33 => 1,
0x34 => 1,
0x50 => 1,
0x51 => 1,
0x52 => 1,
0x55 => 1,
0x5b => 1,
);

# _entry searches for a directory entry.
# Parameters:
# 1. Reference to Identity object
# 2. String or reference to array of strings - An attribute
# 3. String - An attribute like "groupmail".
# Returns:
# 1. String - An error message.
# 2. Net::LDAP::Entry


sub _entry
{
	my ($entity, $attrs, $ou) = @_;
	my $name = $entity->{name};
	my $type = $entity->{'-type'};
	$ou ||= $type;
	my $entry;
# If $attrs is a reference, execute the if statement. Otherwise, return a field from the entity.
	$entry = $entity->{"-ad_${ou}_entry"} unless ref($attrs);
	if (!$entry)
	{
# Get a directory handle or return an error.
		$ldap = _directory();
		ref($ldap) or return $ldap;
# Searches the directory.
		my $search = $ldap->search
		(
			scope => 'sub',
			base => "OU=$ou,$BASE",
			filter => "($DN=$name" . ($ou eq 'groupmail' && '-mbx') . ')',
			attrs => ref($attrs) ? $attrs : $ATTRS,
		);
# If the search is not a success and is one of the retry errors, then try another directory handle and run the search again.
		if ($search->code() && defined($ldap_retry_errors{$search->code()}))
		{
			$ldap = $ldap_dc = undef;
			$ldap = _directory();
			ref($ldap) or return $ldap;
			$search = $ldap->search
			(
				scope => 'sub',
				base => "OU=$ou,$BASE",
				filter => "($DN=$name" . ($ou eq 'groupmail' && '-mbx') . ')',
				attrs => ref($attrs) ? $attrs : $ATTRS,
			);
		}
# If the search fails or returns empty, return an error message. Or update the property in $entity if $attrs is not reference.
		$search->code() and return Identity::log("error getting $ou $name entry: " . $search->error() . ' (' . $search->code() . ')');
		$entry = $search->shift_entry() or return "$name is not an existing $ou";
		$entity->{"-ad_${ou}_entry"} = $entry unless ref($attrs);
	}
	return $entry;
}

# _update updates an entry in a directory.
# Parameters:
# 1. Net::LDAP::Entry
# Returns:
# 1. String - An error if connection fails.
# 2. String - Update fails.
# 3. undef - If successful.
sub _update
{
	my ($entry) = @_;
	my $status;
	my $try = 1;
# Try to update until:
	while (1)
	{
# Connecting to directory failed.
		$ldap = _directory();
		ref($ldap) or return $ldap;
		$status = $entry->update($ldap);
# Updating is a success or the error is serious.
		last unless ($status->code() && defined($ldap_retry_errors{$status->code()}));
		$ldap = undef;
# Too many update failures.
		last unless ($try < $MAX_RETRIES);
		Identity::log("warning: retryable update failure " . $status->error() . ' (' . $status->code() . ')');
		sleep($try * $RETRY_SLEEP);
		$try++;
	};
	return ($status->code() ? $status->error() . ' (' . $status->code() . ')' : undef);
}

# Create user or group
# Parameters:
# $entity - A user or group object reference used as basis.
# Returns:
# void - If disabled or successful.
# string - If cannot connect to directory or if updating failed.
sub create
{
	my ($entity) = @_;
	my $name     = $entity->{name};
	my $type     = $entity->{'-type'};
	my $title    = $entity->{title};
	my $phone    = $entity->{phone};
	my $fax      = $entity->{fax};
	my $location = $entity->{location};
# Creates an Entry object based on the $entity parameter.
	my $entry = Net::LDAP::Entry->new();
	$entry->dn("$DN=$name,ou=$type,$BASE");
	$entry->add(displayName => $title);
# If it is a user, fill in relevant information.
	if ($type eq 'user')
	{
		my $last_name  = $entity->{last_name};
		my $first_name = $entity->{first_name};
		my $mi         = $entity->{mi};
		my $position   = $entity->{position};
		my $emplid     = $entity->{emplid};
		my $ferpa      = $entity->{ferpa};
		($first_name, $mi) = $first_name =~ /\.$/ ? ($mi, undef) : ($first_name, substr($mi, 0, 1) . '.') if length($mi) > 6;
		$entry->add
		(
			objectClass			=> ['top','person','organizationalPerson','user'],
			$DN					=> $name,
			sn					=> $last_name,
			mail				=> "$name\@$DOMAIN",
			wWWHomePage			=> "http://www.$DOMAIN/~$name/",
			homeDirectory		=> "\\\\files.$DOMAIN\\user\\$name",
			homeDrive			=> 'Z:',
			sAMAccountName		=> $name,
			userPrincipalName	=> "$name\@$DOMAIN",
			unicodePwd			=> [ join("\0", split(//, "\"$entity->{password}\"")) . "\0" ],
			userAccountControl	=> '546',
			accountExpires		=> 0,
		);
		$entry->add(givenName => $first_name)    if $first_name;
		$entry->add(initials  => $mi)            if $mi;
		$entry->add(title     => $position->[0]) if $position;
		$entry->add(calstateEduPersonEmplid       => $emplid)     if $emplid;
		$entry->add(calstateEduPersonRestrictFlag => $ferpa)      if $ferpa;
	}
# If not a user, then add relevant information to the Entry object.
	else
	{
		my $visibility = $entity->{visibility} || 'public';
		my $population = $entity->{population};
		$entry->add
		(
			objectClass    => ['top', 'group'],
			sAMAccountName => $name,
			description    => $title,
			cppGroupPopulation => $population,
			# Universal security group, hardcoded constants woo woo
			groupType => '-2147483640',
		);
		$entry->add(cppGroupRestrictFlag => 'member') if $visibility eq 'private';
	}
# Add common information.
	$entry->add(telephoneNumber            => $phone->[0])    if $phone;
	$entry->add(facsimileTelephoneNumber   => $fax->[0])      if $fax;
	$entry->add(physicalDeliveryOfficeName => $location->[0]) if $location;
# If not disabled and can connect to directory, continue.
	return if $disable =~ /r/;
	$ldap = _directory(); ref($ldap) or return $ldap;
	return if $disable =~ /w/;
# Add entry or return error.
	my $status = _update($entry); $status and
	return Identity::log("error adding $type $name to directory: $status");
# Set Entry object as property of entity and return void.
	$entity->{'-ad_entry'} = $entry;
	return;
}

# Delete user or group
# Parameters:
# $entity - Identity object reference
# Returns:
# void - If disabled or successful.
# string - Error messages from getting an Entry or updating.
sub delete
{
	my ($entity) = @_;
	my $name = $entity->{name};
	my $type = $entity->{'-type'};
	return if $disable =~ /r/;
# Get the entry or return an error.
	my $entry           = _entry($entity); ref($entry) or return $entry;
# Get the groupmail entry.
	my $groupmail_entry = $type eq 'group' && _entry($entity, undef, 'groupmail');
	return if $disable =~ /w/;
# Deletes the entry and updates the directory or returns an error.
	$entry->delete();
	my $status = _update($entry);
	$status and return Identity::log("error deleting $type $name: $status");
# Deletes the groupmail entry and updates or returns an error.
	if (ref($groupmail_entry))
	{
		$groupmail_entry->delete();
		$status = _update($groupmail_entry) and return Identity::log("error deleting $type $name mailbox: $status");
	}
	return;
}

# Store user department
# Parameters:
# Returns:
# void - If successful or disabled.
# string - Error messages from getting an entry or writing to the server.
sub department {

	my ($user, $new_department) = @_;

	return if $disable =~ /r/;
# Get the directory entry or return an error. Then get the attribute.
	my $entry = _entry($user); ref($entry) or return $entry;

	my $department = $entry->get_value('department', asref => 1);
# If the new one and the old one are not the same:
	if ($new_department and ($department xor @$new_department) || $department->[0] ne $new_department->[0]) {

		my $name = $user->{name};
# Replace the attribute and logs a message.
		Identity::log("store user $name department $new_department->[0] (was " . ($department && $department->[0]) . ')');

		$entry->replace(department => @$new_department ? $new_department->[0] : []);
# If the server is not disabled, update it or return an error.
		return if $disable =~ /w/;

		my $status = _update($entry); $status and return Identity::log("error storing user $name department: $status");
	}
	return;
}

#######################
# Store user disabled #
#######################

sub disabled {

	my ($user, $new_disabled) = @_;

	if (defined($new_disabled)) {
# return if regex results in match/contains 'r'
		return if $disable =~ /r/;

		my $entry = _entry($user); ref($entry) or return $entry;

		my $control = $entry->get_value('userAccountControl');
# replace user account control to hex 02 or -02 depending on if user account control 
		$entry->replace(userAccountControl => $new_disabled ? $control | 0x02 : $control & ~0x02);

		my $name = $user->{name};
# set new disabled status
		$new_disabled = $new_disabled ? 'T' : 'F';

		Identity::log("store user $name disabled $new_disabled");
# return if regex results in match/contains 'w'
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
# get last change or return no password
	$pwd_lastchange or
		return 'no password change attribute found';
# reset last change
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
#strips additional figures from lockout time
	$lockout_time =~ s/\d{7}$//;
#subtracts init clock time
	$lockout_time -= 134774 * 24 * 60 * 60;

# lockout already expired, not locked out, no need to unlock
	($lockout_time + $lockoutduration > time()) or return;

	if ($unlock) {
		Identity::log("store user $name lockout false");
# reset lockout time
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
# return if disabled
	return if $disable =~ /r/;

	my $entry = _entry($user); ref($entry) or return $entry;
	my $name = $user->{name};
# get last pastword set time
	my $pwd_expired = ($entry->get_value('pwdLastSet') == 0) ? 'T' : 'F';
# if defined, first check if expired
	if (defined($new_pwd_expired)) {
		$new_pwd_expired = $new_pwd_expired =~ /^[Tt1]$/ ? 'T' : 'F';
# if dates not equal
		if ($new_pwd_expired ne $pwd_expired) {
# replace last password expiration with new
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
#extends expiration date of password
	if ($expiration) {
		$expiration =~ s/\d{7}$//;
		$expiration -= 134774 * 24 * 60 * 60;
	}
#check if new expiration is defined and not same as old expiration
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
#Short circuit check to make sure new fax is a new number and not null
	if ($new_fax and ($fax xor @$new_fax) || $fax->[0] ne $new_fax->[0]) {

		my $name = $entity->{name};
		my $type = $entity->{'-type'};

		Identity::log("store $type $name fax $new_fax->[0] (was " . ($fax && $fax->[0]) . ')');
#update fax at proper entry[]
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
#returns if disable is true.
	return if $disable =~ /r/;
# Get the directory entry or return an error. Then get the attribute.
	my $entry = _entry($user); ref($entry) or return $entry;
#Get the homeDirectory from entry.
	my $homedir = $entry->get_value('homeDirectory');
#get name from user.
	my $name = $user->{name};
#if new homedir has value check file type and set according to winfile,zfs,orzfsraw.else return eroor 
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
#if both the homedir not equal to new_homedir then continue
	if ($new_homedir and $homedir ne $new_homedir) {

		$entry->replace(homeDirectory => $new_homedir);
#log user's new homedir
		Identity::log("store user $name homedir $new_homedir (was $homedir)");
#If not disabled update 
		return if $disable =~ /w/;
#else send error if disabled and returns identity log.
		my $status = _update($entry); $status and
			return Identity::log("error storing user $name homedir: $status");
#homedir is set to new one
		$homedir = $new_homedir;
	}
#assign user's homedir to correct homedir.
	$user->{homedir} = $homedir if defined($homedir);
	return;
}

################################
# Store user or group location #
################################

sub location {

	my ($entity, $new_location) = @_;
#returns if disable is true
	return if $disable =~ /r/;
# Get the directory entry or return an error. Then get the attribute.
	my $entry = _entry($entity); ref($entry) or return $entry;
#set location to physicalDeliveryOfficeName in Directory entry
	my $location = $entry->get_value('physicalDeliveryOfficeName', asref => 1);
#if either new location and old location does not equal to new
# OR locations first stored location do not equal continue else return
	if ($new_location and ($location xor @$new_location) || $location->[0] ne $new_location->[0]) {
# set name and type
		my $name = $entity->{name};
		my $type = $entity->{'-type'};
#IDentity server log 
		Identity::log("store $type $name location $new_location->[0] (was " . ($location && $location->[0]) . ')');
#replace entry's PhysicalDeliveryOfficeName to new location
		$entry->replace(physicalDeliveryOfficeName => @$new_location ? $new_location->[0] : []);
#If not disabled update 
		return if $disable =~ /w/;
#else update status and return with Identity server log
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
#set name of group,add array,remove array,populate. 
	my $name     = $group->{name};
	my $populate = $update_members->{populate};
	my $remove   = $update_members->{remove};
	my $add      = $update_members->{add};
#if disabled return
	return if $disable =~ /r/;
# Get the directory entry or return an error. Then get the attribute.
	my $entry = _entry($group); ref($entry) or return $entry;
#declare memebers has and range array; set first
	my %members;
	my @range;
	my $first = 0;
#gets all memebers from said arrays
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
#populate new group
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
#remove users from group
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
#add users if they exist 
	if ($add) {
		my @add_dn;

		foreach my $username (@$add) {
#gets username of user and creates error message.
			next if $members{$username};
			$error .= Identity::log("error adding user $username to group $name: user doesn't exist") and
				next if Identity::type($username) ne 'user';
			push(@add_dn, "$DN=$username,ou=user,$BASE");
			$members{$username} = 1;
		}
		if (@add_dn) {{
#if added store log
			Identity::log("store group $name members +" . @add_dn);
$return if true.
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
#set name and type from entity.
	my $name = $entity->{name};
	my $type = $entity->{'-type'};
#Return if true.
	return if $disable =~ /r/;
# Get the directory entry or return an error. Then get the attribute.
	my $entry           = _entry($entity); ref($entry) or return $entry;
	my $groupmail_entry = $type eq 'group' && _entry($entity, undef, 'groupmail');
	my $error;
#Entry replaces sAMAccount name with new name.
	$entry->replace(
			sAMAccountName    => $new_name,
	);
#if entry mail exist replace with new name.
	if ($entry->exists('mail')) {
		$entry->replace(mail => "$new_name\@" . ($type eq 'group' && 'groups.') . $DOMAIN);
	}
#replace mail nickname if it exist with new name.	
	if ($entry->exists('mailNickname')) {
		$entry->replace(mailNickname => $new_name);
	}
#If address are being forwarded to this email change the forwards.
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
#if type is a user change homedirectory
	if ($type eq 'user') {
		my $home_directory = $entry->get_value('homeDirectory');
		$home_directory =~ s/$name$/$new_name/;
# replace entry attributes		
		$entry->replace(
				homeDirectory     => $home_directory,
				userPrincipalName => "$new_name\@$DOMAIN",
			        wWWHomePage       => "http://www.$DOMAIN/~$new_name/",
				);
#Replace email in directory entry.		
		if ($entry->exists('targetAddress')) {
			$entry->replace(targetAddress => "SMTP:$new_name\@livecsupomona.mail.onmicrosoft.com");
		}
	}
#If group then groupmail's directory entry will replace attributes
	if (ref($groupmail_entry)) {
		$groupmail_entry->replace(
				mail              => "$new_name\@$DOMAIN",
				mailNickname      => "${new_name}-mbx",
				sAMAccountName    => "${new_name}-mbx",
				userPrincipalName => "${new_name}-mbx\@$DOMAIN",
				targetAddress => "SMTP:$new_name\@livecsupomona.mail.onmicrosoft.com",
				);
#Finds proxy adress for email and logs it,then deletes old one and replaces. If statement checks smtp mail server type
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
#return if disable is true.		
	return if $disable =~ /w/;
#check status and creates error message and and log. 
	my $status = _update($entry); $status and
		$error .= Identity::log("error renaming $type $name to $new_name: $status");
#gets LDAP entry and tries to replace it and checks for if not error and deletes.
	$status = $ldap->moddn($entry->dn(),
		newrdn       => "$DN=$new_name",
		deleteoldrdn => 1,
	); $status->code() and
		$error .= Identity::log("error renaming $type $name DN to $new_name: " . $status->error());
 
	delete($entity->{"-ad_${type}_entry"});
#if groupmail then checks status and creates error. Same as user above.
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
#returns if disable is true.
	return if $disable =~ /r/;
# Get the directory entry or return an error. Then get the attribute.
	my $entry = _entry($user); ref($entry) or return $entry;
#replace entry password
	$entry->replace('unicodePwd' => [ join("\0", split(//, "\"$new_password\"")) . "\0" ]);
#gets user name
	my $name = $user->{name};
#log in identity server new password
	Identity::log("store user $name password");
#returns true if disable false.
	return if $disable =~ /w/;
#else check status and return with error log.
	my $status = _update($entry); $status and
		return Identity::log("error storing user $name password: $status");

	return;
}

#############################
# Store user or group phone #
#############################

sub phone {

	my ($entity, $new_phone) = @_;
#return disable is true
	return if $disable =~ /r/;
# Get the directory entry or return an error. Then get the attribute.
	my $entry = _entry($entity); ref($entry) or return $entry;
#get phone from entry.
	my $phone = $entry->get_value('telephoneNumber', asref => 1);
#if new_phone does not match phone or first of phone arrays dont match continue else return
	if ($new_phone and ($phone xor @$new_phone) || $phone->[0] ne $new_phone->[0]) {
#gets entity name and type
		my $name = $entity->{name};
		my $type = $entity->{'-type'};
#logs new phone and old phone in identity server
		Identity::log("store $type $name phone $new_phone->[0] (was " . ($phone && $phone->[0]) . ')');
#directory entry replace number with new number
		$entry->replace(telephoneNumber => @$new_phone ? $new_phone->[0] : []);
#Return if disable is false
		return if $disable =~ /w/;
#update status and returns log if disable is true
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
#Retruns if disable is true
	return if $disable =~ /r/;
# Get the directory entry or return an error. Then get the attribute.
	my $entry = _entry($user); ref($entry) or return $entry;
#get title from entry
	my $position = $entry->get_value('title', asref => 1);
#if new position does not equal old and exist or new and old position arrays do not match continue else return.
	if ($new_position and ($position xor @$new_position) || $position->[0] ne $new_position->[0]) {
#set user name
		my $name = $user->{name};
#Logs on identity server that new position is stored
		Identity::log("store user $name position $new_position->[0] (was " . ($position && $position->[0]) . ')');
#replace in directory
		$entry->replace(title => @$new_position ? $new_position->[0] : []);
#continue is disable is false 
		return if $disable =~ /w/;
#returns error if true
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
# Get the directory entry or return an error. Then get the attribute.
	my $entry = _entry($user); ref($entry) or return $entry;
#get directory entry mi
	my $mi = $entry->get_value('initials');
#if new mi exist and new mi and old mi are not equal
	if ($new_mi && $new_mi ne $mi) {
#get user name
		my $name = $user->{name};
#logs in identity server new mi has been stored
		Identity::log("store user $name mi $new_mi (was $mi)");
#replace in directory entry
		$entry->replace(initials => $new_mi);
#continue if disable is false
		return if $disable =~ /w/;
#returns error on false and updates status
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

# create_date fetches date of group creation
# Parameters:
# $group - Group object reference
# Returns:
# void - If disabled or successful.
# string - If entry or the attribute cannot be found. Or if the date attribute has an invalid format.
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

# Store or fetch user affiliation
# Parameters:
# $user - Reference of User object.
# $new_affiliation - Reference of array of strings - If defined, appends the strings to the attribute.
# Returns:
# 1. void - If the module is disabled for writing or reading. Or if successful.
# 2. string - Error message if the corresponding entry in the directory cannot be found. Or failed to update.
sub affiliation
{
	my ($user, $new_affiliation) = @_;
	return if $disable =~ /r/;
# Gets an entry or returns an error.
	my $entry = _entry($user);
	ref($entry) or return $entry;
	my $affiliation = $entry->get_value('cppEduPersonAffiliation', asref => 1);
# Adds $new_affiliation strings to the entry.
	if (defined($new_affiliation))
	{
# Sorts and turns the arrays from the attribute and argument into strings.
		my $affiliation_string = defined($affiliation) && join(',', sort(@$affiliation));
		my $new_affiliation_string = defined($new_affiliation) && join(',', sort(@$new_affiliation));
		if ($new_affiliation_string ne $affiliation_string)
		{
			my $name = $user->{name};
			my @eduPersonAffiliation;
			my $eduPersonPrimaryAffiliation;
# If the strings are different and are these tags, then add it to the array.
			foreach my $eduPersonAffiliation ('faculty', 'staff', 'employee', 'student', 'member', 'affiliate')
			{
				if (grep($_ eq $eduPersonAffiliation, @$new_affiliation))
				{
					push(@eduPersonAffiliation, $eduPersonAffiliation);
					$eduPersonPrimaryAffiliation ||= $eduPersonAffiliation;
				}
			}
# Update the entry object and then update the directory if not disabled.
			$entry->replace(eduPersonAffiliation => \@eduPersonAffiliation);
			$entry->replace(eduPersonPrimaryAffiliation => $eduPersonPrimaryAffiliation);
			$entry->replace(cppEduPersonAffiliation => $new_affiliation);
			Identity::log("store user $name affiliation $new_affiliation_string (was $affiliation_string)");
			return if $disable =~ /w/;
			my $status = _update($entry);
			$status and return Identity::log("error storing user $name affiliation: " . $status);
			$affiliation = $new_affiliation;
		}
	}
# Update the field.
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

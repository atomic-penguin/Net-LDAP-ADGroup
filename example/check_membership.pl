#!/usr/bin/perl

use Net::LDAP::ADGroup;

my $server = 'example.com';
my $binddn = 'CN=username,CN=Users,DC=example,DC=com';
my $bindpass = 'password';
my @groups_to_check = qw(it-staff foo bar);
my $username = 'username@example.com';

my $ad_group = Net::LDAP::ADGroup->new($server);
$ad_group->bind($binddn, password => $bindpass );

foreach my $group (@groups_to_check) {

  if ( $ad_group->ismember($username, $group) ) {
      print "$username is a member of $group\n";
  } else {
      print "$username is NOT a member of $group\n";
  }

}

my @groups = $ad_group->allgroups($username);

print "$username belongs to groups:\n";
foreach my $group (@groups) {
   print "\t$group\n";
}

$ad_group->unbind;

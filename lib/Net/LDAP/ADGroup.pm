package Net::LDAP::ADGroup;
use 5.008008;
use strict;
use warnings;
use version 0.77; our $VERSION = qv("v0.2.1");

use parent qw(Net::LDAP);

# The following two methods are the most useful,
# and are intended for use by end users.

# ismember Method needs two parameters
# (User SAMAccountName or UPN, and Group SAMAccountName)
# Returns true if User is a member of Group
sub ismember {
    my ( $self, $usersam, $groupsam ) = @_;

    my $userdn = $self->getdnbysam($usersam);
    return 0 if ( $userdn eq q{} );

    my $groupsid = $self->getsidbysam($groupsam);
    return 0 if ( $groupsid eq q{} );

    my @grouptokens = $self->getgrouptokens($userdn);
    my @matches = grep { $_ eq $groupsid } @grouptokens;
    return ( @matches > 0 );
}

# Enumerates groups by SAM name
# Parameters: SAMAccountName or UPN
# Returns: an array of all groups for a given SAM/UPN
sub allgroups {
    my ( $self, $usersam ) = @_;

    my $userdn      = $self->getdnbysam($usersam);
    my @grouptokens = $self->getgrouptokens($userdn);
    my @results;

    foreach my $token (@grouptokens) {
        push @results, $self->getgroupsambysid($token);
    }

    return @results;
}

# The following methods are intended to be called
# from the above "end-user" methods.  However, they are
# available to you, if you have some use for them.

# Get DN by sAMAccountName or userPrincipalName
# Parameters: User SAM or UPN
# Returns User DN
sub getdnbysam {
    my ( $self, $samname ) = @_;

    my $results = $self->search(
        base   => $self->getrootdn,
        filter => "(|(sAMAccountName=$samname)(userPrincipalName=$samname))",
        attrs  => ['distinguishedName']
    );

    if ( $results->count ) {
        return $results->entry(0)->get_value('distinguishedName');
    }
}

# Get SID by sAMAccountName or UPN
# Parameters: User/Group SAM or User UPN
# Returns: objectSid
sub getsidbysam {
    my ( $self, $samname ) = @_;

    my $results = $self->search(
        base   => $self->getrootdn,
        filter => "(|(sAMAccountName=$samname)(userPrincipalName=$samname))",
        attrs  => ['objectSid']
    );

    if ( $results->count ) {
        return $results->entry(0)->get_value('objectSid');
    }
}

# GetTokenGroups takes one parameter
# (User Distinguished Name)
# Returns: Group Tokens
sub getgrouptokens {
    my ( $self, $userdn ) = @_;

    my $results = $self->search(
        base   => $userdn,
        scope  => 'base',
        filter => '(&(objectClass=user)(objectClass=person))',
        attrs  => ['tokenGroups']
    );

    if ( $results->count ) {
        return $results->entry(0)->get_value('tokenGroups');
    }
}

# Get sAMAccountName by object's SID
# Parameters: Group token SID number
# Returns Group SAM Account Name
sub getgroupsambysid {
    my ( $self, $groupsid ) = @_;

    my $results = $self->search(
        base   => '<SID=' . unpack( 'H*', $groupsid ) . '>',
        scope  => 'base',
        filter => '(objectCategory=*)',
        attrs  => ['sAMAccountName']
    );

    if ( $results->count ) {
        return $results->entry(0)->get_value('sAMAccountName');
    }
}

# Returns the Root DN of logged in domain
# (DC=example,DC=com)
sub getrootdn {
    my ($self) = @_;
    return ( $self->root_dse->get_value('namingContexts') )[0];
}

1;
__END__

=head1 NAME

Net::LDAP::ADGroup - Basic Perl extension of Net::LDAP for querying group membership

=head1 VERSION

This documentation refers to <Net::LDAP::ADGroup> version 0.2.

=head1 SYNOPSIS

=head2 EXAMPLE USAGE

  use Net::LDAP::ADGroup;

  my $adgroup_obj = Net::LDAP::ADGroup->new( $server );
  my $adgroup_obj->bind( $binddn, password => $bindpass );

  my $boolean = $adgroup_obj->ismember( $username, $groupname );
  my @groups = $adgroup_obj->allgroups( $username );

  $adgroup_obj->unbind;

=head1 DESCRIPTION

This was my first attempt at an Object Oriented Perl module.  In other words,
it was a learning experience, and the code may not prove to be very useful to
anyone, but myself.

This code was heavily influenced by Shawn Poulson's ADGroupExample.pl script
which can be found on his Exploding Coder Blog (http://explodingcoder.com).
ADGroupExample.pl is Copyright (C) 2009 Shawn Poulson.

=head1 SUBROUTINES/METHODS

An object of this class represents an inherited child-class of Net::LDAP.
You need to instantiate the object the same way you would a Net::LDAP object.
You can do this by calling methods, new and bind.  Also, I recommend calling
the unbind method at the end of your script to disconnect gracefully from
LDAP.

Specifically, the following two methods will return useful information, when
passed a specific sAMAccountName or userPrincipalName to look up in Active
Dirctory.

The first method, ismember, also requires a group name to check
group membership.  This method will resolve recursive group membership.

The second method, allgroups, requires only a sAMAccountName or
userPrincipalName to return all group memberships recursively by an array
structure.  Specifically the group names returned are the LDAP attribute
sAMAccountName belonging to those groups. This is not to be confused with
an user's sAMAccountName LDAP attribute.

=over

=item ismember

$object->ismember( $sam_or_upn, $activedirectory_group ); # Returns a boolean if a member of A.D. Group

=item allgroups

$object->allgroups( $sam_or_upn ); #Returns an array of group names

=back

=head2 INHERITED METHODS

=over

=item Net::LDAP::ADGroup::new

$object->new( $server ); # Create new Net::LDAP::ADGroup object

=item Net::LDAP::ADGroup::bind

$object->bind( $binddn, password => $bindpass ); # Authenticate to LDAP server

=item Net::LDAP::ADGroup::unbind

$object->unbind; # Disconnect from LDAP server

=back

=head1 DIAGNOSTICS

=head2 LDAP ERROR CODES

Net::LDAP also exports constants for the error codes that can be received from the server, see Net::LDAP::Constant.

=head1 CONFIGURATION AND ENVIRONMENT

See L<Net::LDAP/CONSTRUCTOR> for more information on what options can be passed to the method "new".

=head1 DEPENDENCIES

Strongly recommend installing L<Bundle::Net::LDAP>. However, you can probably
get by with installing L<Net::LDAP> from CPAN or a package manager.

You will need the modules, L<version> v0.77 and L<parent>.  The L<parent>
module was forked from the L<base> module.

=head1 INCOMPATIBILITIES

None known

=head1 BUGS AND LIMITATIONS

There are no known bugs in this application.
Please report problems to:

=over

=item Eric G. Wolfe E<lt>wolfe21 (at) marshall (dot) eduE<gt>

=back

=head1 SEE ALSO

The base class for this module is L<Net::LDAP>.  The only methods from
L<Net::LDAP> which were tested are: new; bind; unbind.  Other methods may work
with this module but I did not, and will not, test them.

The example folder contains a script with example code using this module.

The newest version of this code can be downloaded from http://webpages.marshall.edu/~wolfe21

=head1 AUTHOR

Eric G. Wolfe, E<lt>wolfe21 (at) marshall (dot) eduE<gt>

=head1 LICENSE AND COPYRIGHT

Copyright (C) 2010 by Eric G. Wolfe, E<lt>wolfe21 (at) marshall (dot) eduE<gt>. All rights reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.1 or,
at your option, any later version of Perl 5 you may have available.

=cut

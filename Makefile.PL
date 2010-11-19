use 5.008008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::LDAP::ADGroup',
    VERSION_FROM      => 'lib/Net/LDAP/ADGroup.pm', # finds $VERSION
    PREREQ_PM         => { version => 0.77, Net::LDAP => 0.30, parent => 0.215 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Net/LDAP/ADGroup.pm', # retrieve abstract from module
       AUTHOR         => 'Eric G. Wolfe <wolfe21@marshall.edu>') : ()),
);

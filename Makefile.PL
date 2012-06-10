## no critic (RCS,VERSION,interpolation)
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME               => 'Class::User::DBI',
    AUTHOR             => q{David Oswald <davido [@at] cpan [d.o.t] org>},
    VERSION_FROM       => 'lib/Class/User/DBI.pm',
    ABSTRACT_FROM      => 'lib/Class/User/DBI.pm',
    LICENSE            => 'perl',
    MIN_PERL_VERSION   => '5.008000',
    PL_FILES           => {},
    CONFIGURE_REQUIRES => { 'ExtUtils::MakeMaker' => '6.62', },
    BUILD_REQUIRES     => {
        'Test::More'  => '0.98',
        'DBD::SQLite' => 0,
    },
    PREREQ_PM => {
        'Test::More'                       => 0,
        'Authen::Passphrase::SaltedSHA512' => 0,
        'DBIx::Connector'                  => 0,
        'List::MoreUtils'                  => 0,
    },
    META_MERGE => {
        provides  => 'Class::User::DBI.pm',
        version   => '0.02',
        resources => {
            repository => {
                web  => 'http://github.com/daoswald/Class-User-DBI.git',
                url  => 'git://github.com/daoswald/Class-User-DBI.git',
                type => 'git',
            },
        },
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES    => 'Class-User-DBI-*' },
);

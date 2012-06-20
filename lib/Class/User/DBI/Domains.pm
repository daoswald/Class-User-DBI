## no critic (RCS,VERSION)
package Class::User::DBI::Domains;

use strict;
use warnings;

use Carp;

use Class::User::DBI::DB qw( db_run_ex  %DOM_QUERY );

our $VERSION = '0.01_003';
$VERSION = eval $VERSION;    ## no critic (eval)

# Class methods.

sub new {
    my ( $class, $conn ) = @_;
    my $self = bless {}, $class;
    croak 'Constructor called without a DBIx::Connector object.'
      if !ref $conn || !$conn->isa('DBIx::Connector');
    $self->{_db_conn} = $conn;
    $self->{domains}  = {};
    return $self;
}

sub configure_db {
    my ( $class, $conn ) = @_;
    croak 'Must provide a valid constructor object.'
      if !ref $conn || !$conn->isa('DBIx::Connector');
    $conn->run(
        fixup => sub {
            $_->do( $DOM_QUERY{SQL_configure_db_cud_domains} );
        }
    );
    return 1;
}

# Object methods.

sub _db_conn {
    my $self = shift;
    return $self->{_db_conn};
}

# Usage:
# $dom->exists_domain( $domain );
# returns 0 or 1.
sub exists_domain {
    my ( $self, $domain ) = @_;
    croak 'Must pass a defined value in domain test.'
      if !defined $domain;
    croak 'Must pass a non-empty value in domain test.'
      if !length $domain;
    return 1 if exists $self->{domains}{$domain};
    my $sth =
      db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_exists_domain}, $domain );
    my $result = defined $sth->fetchrow_array;
    $self->{domains}{$domain}++ if $result;    # Cache the result.
    return $result;
}

# Usage:
# $dom->add_domains( [ qw( domain description ) ], [...] );
# Returns the number of domains actually added.

sub add_domains {
    my ( $self, @domains ) = @_;
    my @domains_to_insert =
      grep { ref $_ eq 'ARRAY' && $_->[0] && !$self->exists_domain( $_->[0] ) }
      @domains;

    # Set undefined descriptions to q{}.
    foreach my $dom_bundle (@domains_to_insert) {

        # This change is intended to propagate back to @domains_to_insert.
        $dom_bundle->[1] = q{} if !$dom_bundle->[1];
    }
    my $sth = db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_add_domains},
        @domains_to_insert );
    return scalar @domains_to_insert;
}

# Deletes all domains in @domains (if they exist).
# Silent if non-existent. Returns the number of domains actually deleted.
sub delete_domains {
    my ( $self, @domains ) = @_;
    my @domains_to_delete;
    foreach my $domain (@domains) {
        next if !$domain || !$self->exists_domain($domain);
        push @domains_to_delete, [$domain];
        delete $self->{domains}{$domain};    # Remove it from the cache too.
    }
    my $sth = db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_delete_domains},
        @domains_to_delete );
    return scalar @domains_to_delete;
}

# Gets the description for a single domain.  Must specify a valid domain.
sub get_domain_description {
    my ( $self, $domain ) = @_;
    croak 'Must specify a domain.'
      if !defined $domain;
    croak 'Specified domain must exist.'
      if !$self->exists_domain($domain);
    my $sth =
      db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_get_domain_description},
        $domain );
    return ( $sth->fetchrow_array )[0];
}

# Pass a domain and a new description.  All parameters required.  Description
# of q{} deletes the description.
sub set_domain_description {
    my ( $self, $domain, $description ) = @_;
    croak 'Must specify a domain.'
      if !defined $domain;
    croak 'Specified domain doesn\'t exist.'
      if !$self->exists_domain($domain);
    croak 'Must specify a description (q{} is ok too).'
      if !defined $description;
    my $sth =
      db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_set_domain_description},
        $description, $domain );
    return 1;
}

# Returns an array of pairs (AoA).  Pairs are [ domain, description ],...
sub fetch_domains {
    my $self    = shift;
    my $sth     = db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_list_domains} );
    my @domains = @{ $sth->fetchall_arrayref };
    return @domains;
}

1;

__END__

=head1 NAME

Class::User::DBI - A User class: Login credentials and roles.

=head1 VERSION

Version 0.01_001

=head1 SYNOPSIS

Through a DBIx::Connector object, this module models a "User" class, with
login credentials, and access roles.  Login credentials include a passphrase,
and optionally per user IP whitelisting.

    # Set up a connection using DBIx::Connector:
    # MySQL database settings:

    my $conn = DBIx::Connector->new(
        'dbi:mysql:database=cudbi_tests, 'testing_user', 'testers_pass',
        {
            RaiseError => 1,
            AutoCommit => 1,
        }
    );


    # Now we can play with Class::User::DBI:

    Class::User::DBI->configure_db( $conn );  # Set up the tables for a user DB.

    my @user_list = Class::User::DBI->list_users;

    my $user = new( $conn, $userid );



=head1 DESCRIPTION


=head1 EXPORT

Nothing is exported.  There are many object methods, and three class methods,
described in the next section.


=head1 SUBROUTINES/METHODS


=head2  new
(The constructor -- Class method.)

    my $user_obj = Class::User::DBI->new( $connector, $userid );


=head2  configure_db
(Class method)

    Class::User::DBI->configure_db( $connector );

This is a class method.  Pass a valid DBIx::Connector as a parameter.  Builds
a minimal set of database tables in support of the Class::User::DBI.

The tables created will be C<users>, C<user_ips>, and C<user_roles>.


=head1 DEPENDENCIES


=head1 CONFIGURATION AND ENVIRONMENT



=head1 DIAGNOSTICS

If you find that your particular database engine is not playing nicely with the
test suite from this module, it may be necessary to provide the database login 
credentials for a test database using the same engine that your application 
will actually be using.  You may do this by setting C<$ENV{CUDBI_TEST_DSN}>,
C<$ENV{CUDBI_TEST_DATABASE}, C<$ENV{CUDBI_TEST_USER}>, 
and C<$ENV{CUDBI_TEST_PASS}>.

Currently the test suite tests against a SQLite database since it's such a
lightweight dependency for the testing.  The author also uses this module
with several MySQL databases.  As you're configuring your database, providing
its credentials to the tests and running the test scripts will offer really 
good diagnostics if some aspect of your database tables proves to be at odds 
with what this module needs.

Be advised that the the test suite drops its tables after completion, so be sure
to run the test suite only against a database set up explicitly for testing
purposes.

=head1 INCOMPATIBILITIES

This module has only been tested on MySQL and SQLite database engines.  If you
are successful in using it with other engines, please send me an email detailing
any additional configuration changes you had to make so that I can document
the compatibility, and improve the documentation for the configuration process.

=head1 BUGS AND LIMITATIONS

=head1 AUTHOR


David Oswald, C<< <davido at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-class-user-dbi at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Class-User-DBI>.  I will be
notified, and then you'll automatically be notified of progress on your bug as
I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Class::User::DBI


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Class-User-DBI>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Class-User-DBI>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Class-User-DBI>

=item * Search CPAN

L<http://search.cpan.org/dist/Class-User-DBI/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 David Oswald.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

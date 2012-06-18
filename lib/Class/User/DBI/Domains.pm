package Class::User::DBI::Domains;

use strict;
use warnings;

use Carp;

use Class::User::DBI::DB qw( _db_run_ex  %DOM_QUERY );

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
    croak "Must pass a defined value in domain test."
      if !defined $domain;
    croak "Must pass a non-empty value in domain test."
      if !length $domain;
    return 1 if exists $self->{domains}{$domain};
    my $sth =
      _db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_exists_domain}, $domain );
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
    my $sth = _db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_add_domains},
        @domains_to_insert );
    return scalar @domains_to_insert;
}

# Deletes all domains in @domains (if they exist).
# Silent if non-existent. Returns the number of domains actually deleted.
sub delete_domains {
    my ( $self, @domains ) = @_;
    my @domains_to_delete;
    foreach my $domain (@domains) {
        next if !$domain or !$self->exists_domain($domain);
        push @domains_to_delete, [$domain];
        delete $self->{domains}{$domain};    # Remove it from the cache too.
    }
    my $sth = _db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_delete_domains},
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
      _db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_get_domain_description},
        $domain );
    return ( $sth->fetchrow_array )[0];
}

# Pass a domain and a new description.  All parameters required.  Description
# of q{} deletes the description.
sub update_domain_description {
    my ( $self, $domain, $description ) = @_;
    croak 'Must specify a domain.'
      if !defined $domain;
    croak 'Specified domain doesn\'t exist.'
      if !$self->exists_domain($domain);
    croak 'Must specify a description (q{} is ok too).'
      if !defined $description;
    my $sth =
      _db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_update_domain_description},
        $description, $domain );
    return 1;
}

# Returns an array of pairs (AoA).  Pairs are [ domain, description ],...
sub fetch_domains {
    my $self    = shift;
    my $sth     = _db_run_ex( $self->_db_conn, $DOM_QUERY{SQL_list_domains} );
    my @domains = @{ $sth->fetchall_arrayref };
    return @domains;
}

1;

__END__

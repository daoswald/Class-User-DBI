## no critic (RCS,VERSION)
package Class::User::DBI::Roles;

use strict;
use warnings;

use Carp;

use Class::User::DBI::DB qw( db_run_ex  %ROLE_QUERY );

our $VERSION = '0.01_003';
$VERSION = eval $VERSION;    ## no critic (eval)

# Two tables: One table is role, description.  Second table is role, privilege.
# Second table allows duplicate roles, but not duplicate role/priv.
# This may be two classes: One for the role/description table, and one for the
# roles/privileges table.

# Class methods.

sub new {
    my ( $class, $conn ) = @_;
    my $self = bless {}, $class;
    croak 'Constructor called without a DBIx::Connector object.'
      if !ref $conn || !$conn->isa('DBIx::Connector');
    $self->{_db_conn} = $conn;
    $self->{roles}    = {};
    return $self;
}

sub configure_db {
    my ( $class, $conn ) = @_;
    croak 'Must provide a valid constructor object.'
      if !ref $conn || !$conn->isa('DBIx::Connector');
    $conn->run(
        fixup => sub {
            $_->do( $ROLE_QUERY{SQL_configure_db_cud_roles} );
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
# $role->exists_role( $some_role );
# returns 0 or 1.
sub exists_role {
    my ( $self, $role ) = @_;
    croak 'Must pass a defined value in role test.'
      if !defined $role;
    croak 'Must pass a non-empty value in role test.'
      if !length $role;
    return 1 if exists $self->{roles}{$role};
    my $sth = db_run_ex( $self->_db_conn, $ROLE_QUERY{SQL_exists_role}, $role );
    my $result = defined $sth->fetchrow_array;
    $self->{roles}{$role}++ if $result;    # Cache the result.
    return $result;
}

# Usage:
# $role->add_roles( [ qw( role description ) ], [...] );
# Returns the number of roles actually added.

sub add_roles {
    my ( $self, @roles ) = @_;
    my @roles_to_insert =
      grep { ref $_ eq 'ARRAY' && $_->[0] && !$self->exists_role( $_->[0] ) }
      @roles;

    # Set undefined descriptions to q{}.
    foreach my $role_bundle (@roles_to_insert) {

        # This change is intended to propagate back to @roles_to_insert.
        $role_bundle->[1] = q{} if !$role_bundle->[1];
    }
    my $sth =
      db_run_ex( $self->_db_conn, $ROLE_QUERY{SQL_add_roles},
        @roles_to_insert );
    return scalar @roles_to_insert;
}

# Deletes all roles in @roles (if they exist).
# Silent if non-existent. Returns the number of roles actually deleted.
sub delete_roles {
    my ( $self, @roles ) = @_;
    my @roles_to_delete;
    foreach my $role (@roles) {
        next if !$role || !$self->exists_role($role);
        push @roles_to_delete, [$role];
        delete $self->{roles}{$role};    # Remove it from the cache too.
    }
    my $sth = db_run_ex( $self->_db_conn, $ROLE_QUERY{SQL_delete_roles},
        @roles_to_delete );
    return scalar @roles_to_delete;
}

# Gets the description for a single role.  Must specify a valid role.
sub get_role_description {
    my ( $self, $role ) = @_;
    croak 'Must specify a role.'
      if !defined $role;
    croak 'Specified role must exist.'
      if !$self->exists_role($role);
    my $sth =
      db_run_ex( $self->_db_conn, $ROLE_QUERY{SQL_get_role_description},
        $role );
    return ( $sth->fetchrow_array )[0];
}

# Pass a role and a new description.  All parameters required.  Description
# of q{} deletes the description.
sub update_role_description {
    my ( $self, $role, $description ) = @_;
    croak 'Must specify a role.'
      if !defined $role;
    croak 'Specified role doesn\'t exist.'
      if !$self->exists_role($role);
    croak 'Must specify a description (q{} is ok too).'
      if !defined $description;
    my $sth =
      db_run_ex( $self->_db_conn, $ROLE_QUERY{SQL_update_role_description},
        $description, $role );
    return 1;
}

# Returns an array of pairs (AoA).  Pairs are [ role, description ],...
sub fetch_roles {
    my $self  = shift;
    my $sth   = db_run_ex( $self->_db_conn, $ROLE_QUERY{SQL_list_roles} );
    my @roles = @{ $sth->fetchall_arrayref };
    return @roles;
}

1;

__END__

## no critic (RCS,VERSION)
package Class::User::DBI::RolePrivileges;

use strict;
use warnings;

use Carp;

use Class::User::DBI::DB qw( db_run_ex  %RP_QUERY );
use Class::User::DBI::Roles;
use Class::User::DBI::Privileges;

our $VERSION = '0.01_003';
$VERSION = eval $VERSION;    ## no critic (eval)

# Table is role, privilege.
# Table allows duplicate roles, but not duplicate role/priv.

# Class methods.

sub new {
    my ( $class, $conn, $role ) = @_;
    croak 'Constructor called without a DBIx::Connector object.'
      if !ref $conn || !$conn->isa('DBIx::Connector');
    my $self = bless {}, $class;
    $self->{_db_conn} = $conn;
    my $r = Class::User::DBI::Roles->new( $self->_db_conn );
    croak 'Constructor called without passing a valid role by name.'
      if !defined $role
          || !length $role
          || !$r->exists_role($role);
    $self->{role} = $role;
    return $self;
}

sub configure_db {
    my ( $class, $conn ) = @_;
    croak 'Must provide a valid constructor object.'
      if !ref $conn || !$conn->isa('DBIx::Connector');
    $conn->run(
        fixup => sub {
            $_->do( $RP_QUERY{SQL_configure_db_cud_roleprivs} );
        }
    );
    return 1;
}

# Object methods.

sub _db_conn {
    my $self = shift;
    return $self->{_db_conn};
}

sub get_role {
    my $self = shift;
    return $self->{role};
}

# Usage:
# $role->exists_role( $some_role );
# returns 0 or 1.
sub has_privilege {
    my ( $self, $privilege ) = @_;
    croak 'Must pass a defined value in privilege test.'
      if !defined $privilege;
    croak 'Must pass a non-empty value in privilege test.'
      if !length $privilege;
    my $p = Class::User::DBI::Privileges->new( $self->_db_conn );
    croak 'Attempt to test a non-existent privilege.'
      if !$p->exists_privilege($privilege);
    return 1
      if exists $self->{privileges}{$privilege}
          && $self->{privileges}{$privilege};
    my $sth = db_run_ex( $self->_db_conn, $RP_QUERY{SQL_exists_priv},
        $self->get_role, $privilege );
    my $result = defined $sth->fetchrow_array;
    $self->{privileges}{$privilege}++ if $result;    # Cache the result.

    return $result;
}

# Usage:
# $r->add_privileges( qw( privileges ) );
# Returns the number of privileges actually added to the role.

sub add_privileges {
    my ( $self, @privileges ) = @_;
    my $p               = Class::User::DBI::Privileges->new( $self->_db_conn );
    my @privileges_to_insert = grep {
             defined $_
          && length $_
          && $p->exists_privilege($_)
          && !$self->has_privilege($_)
    } @privileges;
    $self->{privileges}{$_}++ for @privileges_to_insert;    # Cache.
      # Transform the array of privileges to an AoA of [ $role, $priv ] packets.
    @privileges_to_insert =
      map { [ $self->get_role, $_ ] } @privileges_to_insert;
    my $sth = db_run_ex( $self->_db_conn, $RP_QUERY{SQL_add_privileges},
        @privileges_to_insert );
    return scalar @privileges_to_insert;
}

# Deletes all roles in @roles (if they exist).
# Silent if non-existent. Returns the number of roles actually deleted.
sub delete_privileges {
    my ( $self, @privileges ) = @_;
    my @privileges_to_delete;
    foreach my $privilege (@privileges) {
        next
          if !defined $privilege
              || !length $privilege
              || !$self->has_privilege($privilege);
        push @privileges_to_delete, [ $self->get_role, $privilege ];
        delete $self->{privileges}{$privilege};    # Remove from cache.
    }
    my $sth = db_run_ex( $self->_db_conn, $RP_QUERY{SQL_delete_privileges},
        @privileges_to_delete );
    return scalar @privileges_to_delete;
}

# Returns a list of priviliges for this object's role.
sub fetch_privileges {
    my $self = shift;
    my $sth  = db_run_ex( $self->_db_conn, $RP_QUERY{SQL_list_privileges},
        $self->get_role );
    my @privileges = map { $_->[0] } @{ $sth->fetchall_arrayref };
    $self->{priviliges} = {    # Construct an anonymous hash.
        map { $_ => 1 } @privileges
    };    # Refresh the cache.
    return @privileges;
}

1;

__END__


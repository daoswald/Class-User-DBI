## no critic (RCS,VERSION)
package Class::User::DBI;

use 5.008;

use strict;
use warnings;

use Socket qw( inet_ntoa inet_aton );

use List::MoreUtils qw( any );

use Authen::Passphrase::SaltedSHA512;

use Class::User::DBI::DB qw( %QUERY );

our $VERSION = '0.01_001';
$VERSION = eval $VERSION;    ## no critic (eval)

sub new {
    my ( $class, $db_conn, $userid ) = @_;

    # Reject any userid that is either undefined or evaluates to false.
    return if !defined $userid || !$userid;
    my $self = bless {}, $class;
    $self->{_db_conn}    = $db_conn;
    $self->{userid}      = lc $userid;
    $self->{validated}   = 0;            # Start out with a non-validated user.
    $self->{exists_user} = 0;            # Start with an unproven existence.
    return $self;
}

# Accessors.

sub userid {
    my $self = shift;
    return $self->{userid};
}

sub _db_conn {
    my $self = shift;
    return $self->{_db_conn};
}

sub update_email {
    my ( $self, $new_email ) = @_;
    return if !$self->exists_user;
    my $sth = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_update_email},
        $new_email, $self->userid );
    return $new_email;
}

sub update_username {
    my ( $self, $new_username ) = @_;
    return if !$self->exists_user;
    my $sth =
      $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_update_username},
        $new_username, $self->userid );
    return $new_username;
}

# Check validated status.  Also allow for invalidation by passing a false
# parameter to the method.
sub validated {
    my ( $self, $new_value ) = @_;
    if ( defined $new_value && !$new_value ) {
        $self->{validated} = 0;
    }
    return $self->{validated};
}

# Prepares and executes a database command using DBIx::Connector's 'run'
# method.  Pass bind values as 2nd+ parameter(s).  If the first bind-value
# element is an array ref, bind value params will be executed in a loop,
# dereferencing each element's list upon execution:
# $self->_db_run_ex( 'SQL GOES HERE', @execute_params ); .... OR....
# $self->_db_run_ex(
#     'SQL GOES HERE',
#     [ first param list ], [ second param list ], ...
# );

sub _db_run_ex {
    my ( $self, $sql, @ex_params ) = @_;
    my $conn = $self->_db_conn;
    my $sth  = $conn->run(
        fixup => sub {
            my $sub_sth = $_->prepare($sql);

            # Pass an array of arrayrefs if execute() is to be called in a loop.
            if ( @ex_params && ref( $ex_params[0] ) eq 'ARRAY' ) {
                foreach my $param (@ex_params) {
                    $sub_sth->execute( @{$param} );
                }
            }
            else {
                $sub_sth->execute(@ex_params);
            }
            return $sub_sth;
        }
    );
    return $sth;
}

# Fetches all IP's that are whitelisted for the user.
sub fetch_valid_ips {
    my $self = shift;
    my $sth =
      $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_fetch_valid_ips},
        $self->userid );
    my $rv = [];
    while ( defined( my $row = $sth->fetchrow_arrayref ) ) {
        if ( defined $row->[0] ) {
            push @{$rv}, inet_ntoa( pack 'N', $row->[0] );
        }
    }
    return $rv;
}

# Fetch user's salt_hex, pass_hex, ip_required, and valid ip's from database.
sub fetch_user {
    my $self = shift;
    my $sth  = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_fetch_user},
        $self->userid );
    my ( $salt_hex, $pass_hex, $ip_required ) = $sth->fetchrow_array;
    return if not defined $salt_hex;    # User wasn't found.
    my $valid_ips = $self->fetch_valid_ips;
    return {
        userid      => $self->userid,
        salt_hex    => $salt_hex,
        pass_hex    => $pass_hex,
        ip_required => $ip_required,
        valid_ips   => $valid_ips,
    };
}

sub validate_user {
    my ( $self, $password, $ip, $force_revalidate ) = @_;

    # Save ourselves work if user is already authenticated.
    if ( $self->validated ) {
        return $self->userid;
    }
    my $credentials = $self->fetch_user;
    my $auth        = Authen::Passphrase::SaltedSHA512->new(
        salt_hex => $credentials->{salt_hex},
        hash_hex => $credentials->{pass_hex}
    );

    # Return undef if password doesn't authenticate for the user.
    return unless $auth->match($password);    ## no critic (postfix)

    # Return undef if an IP is required, and IP param is not in whitelist.
    if ( $credentials->{ip_required} ) {
        ## no critic (postfix)
        return unless defined $ip;            # Reject if no IP param.
        return unless any { $ip eq $_ } @{ $credentials->{valid_ips} };
    }

    # We passed! Authenticate.
    $self->{validated} = 1;    # Set in object that we're authenticated.
    return $self->userid;
}

# Quick check whether a userid exists in the database.
# Return undef if user doesn't exist.
sub exists_user {
    my $self = shift;
    return $self->{exists_user}
      if $self->{exists_user};    # Only query if we have to.
    my $sth = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_exists_user},
        $self->userid );
    return $sth->fetchrow_array;    # Will be undef if user doesn't exist.
}

# May be useful later on if we add user information.
sub load_user {
    my $self = shift;
    my $sth  = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_load_user},
        $self->userid );
    my $hr = $sth->fetchrow_hashref;
    return $hr;
}

sub add_ips {
    my ( $self, $ips_aref ) = @_;
    return if !$self->exists_user;

    # We don't want to insert IP's already in the DB.
    my $ips_in_db = $self->fetch_valid_ips;
    my %uniques;
    @uniques{ @{$ips_in_db} } = ();
    my @ips_to_insert = grep { !exists $uniques{$_} } @{$ips_aref};
    return 0 if !@ips_to_insert;

    # Prepare the userid,ip bundles for our insert query.
    ## no critic (builtin)
    my @execution_param_bundles =
      map { [ $self->userid, unpack( 'N', inet_aton($_) ) ] } @ips_to_insert;
    my $sth = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_add_ips},
        @execution_param_bundles );

    return scalar @ips_to_insert;    # Return a count of IP's inserted.
}

sub delete_ips {
    my ( $self, $ips_aref ) = @_;
    return if !$self->exists_user;
    my $ips_in_db = $self->fetch_valid_ips;
    my %found;
    @found{ @{$ips_in_db} } = ();
    my @ips_for_deletion = grep { exists $found{$_} } @{$ips_aref};
    ## no critic (Builtin)
    my @execution_param_bundles =
      map { [ $self->userid, unpack( 'N', inet_aton($_) ) ] } @ips_for_deletion;
    my $sth = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_delete_ips},
        @execution_param_bundles );
    return scalar @ips_for_deletion;    # Return a count of IP's deleted.
}

sub add_user {
    my ( $self, $userinfo ) = @_;

    my $password = $userinfo->{password};
    return if not length $password;     # We require a password.
    return if $self->exists_user;

    my $ip_req   = $userinfo->{ip_req}   // 0;     # Default to not required.
    my $username = $userinfo->{username} // q{};
    my $email    = $userinfo->{email}    // q{};

    my $ips_aref =
      exists( $userinfo->{ips_aref} )
      ? $userinfo->{ips_aref}
      : $userinfo->{ips};                          # Detect later if missing.

    return if $ip_req && !ref $ips_aref eq 'ARRAY';

    my $passgen =
      Authen::Passphrase::SaltedSHA512->new( passphrase => $password );
    my $salt_hex = $passgen->salt_hex;
    my $hash_hex = $passgen->hash_hex;
    $self->_db_conn->txn(
        fixup => sub {
            my $sth = $_->prepare( $Class::User::DBI::DB::QUERY{SQL_add_user} );
            $sth->execute( $self->userid, $salt_hex, $hash_hex, $ip_req,
                $username, $email );
            if ( ref($ips_aref) eq 'ARRAY' ) {
                $self->add_ips($ips_aref);
            }
        }
    );
    $self->{exists_user} = $self->userid;
    return $self->userid;
}

sub update_password {
    my ( $self, $oldpass, $newpass ) = @_;

    return if !$self->exists_user;

    my $credentials = $self->fetch_user;
    my $auth        = Authen::Passphrase::SaltedSHA512->new(
        salt_hex => $credentials->{salt_hex},
        hash_hex => $credentials->{pass_hex}
    );

    # Return undef if password doesn't authenticate for the user.
    return unless $auth->match($oldpass);    ## no critic (postfix)

    my $passgen =
      Authen::Passphrase::SaltedSHA512->new( passphrase => $newpass );
    my $salt_hex = $passgen->salt_hex;
    my $hash_hex = $passgen->hash_hex;
    $self->_db_conn->txn(
        fixup => sub {
            my $sth =
              $_->prepare( $Class::User::DBI::DB::QUERY{SQL_update_password} );
            $sth->execute( $salt_hex, $hash_hex, $self->userid );
        }
    );
    return $self->userid;
}

sub delete_user {
    my $self = shift;
    return if !$self->exists_user;    # undef if user wasn't in the DB.
    $self->_db_conn->txn(
        fixup => sub {
            my $sth =
              $_->prepare(
                $Class::User::DBI::DB::QUERY{SQL_delete_user_users} );
            $sth->execute( $self->userid );
            my $sth2 =
              $_->prepare( $Class::User::DBI::DB::QUERY{SQL_delete_user_ips} );
            $sth2->execute( $self->userid );
            my $sth3 =
              $_->prepare(
                $Class::User::DBI::DB::QUERY{SQL_delete_user_roles} );
            $sth3->execute( $self->userid );
        }
    );
    $self->validated(0);    # Invalidate the deleted user, just in case it was
                            # also the current user.
    $self->{exists_user} = 0;    # Invalidate the exists_user cache.
    return 1;
}

# my $cans_aref = $user->fetch_roles;
# my $success      = $user->add_role( $new_role );
# my $success     = $user->delete_role( $old_role );
# my $can_do    = $user->can_role( $role_to_test );

sub fetch_roles {
    my $self = shift;
    return if !$self->exists_user;
    my $sth = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_fetch_roles},
        $self->userid );
    my $roles_aoa = $sth->fetchall_arrayref;
    my $roles_aref = [ map { $_->[0] } @{$roles_aoa} ];
    return $roles_aref;
}

sub can_role {
    my ( $self, $role ) = @_;
    return if !$self->exists_user;
    my $sth = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_can_role},
        $self->userid, $role );
    return $sth->fetchrow_array;
}

sub add_role {
    my ( $self, $role ) = @_;
    return if !$self->exists_user;
    return if !defined $role || !$role;    # Prevent undefined or 'false' roles.
    return $role if $self->can_role($role);
    my $sth = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_add_role},
        $self->userid, $role );
    return $role;
}

sub delete_role {
    my ( $self, $role ) = @_;
    return if !$self->exists_user;
    my $sth = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_delete_role},
        $self->userid, $role );
    return $self->userid;
}

# Class methods

sub list_users {
    my ( $class, $conn ) = @_;
    my $self = $class->new( $conn, 'dummy_class_user' );
    my $sth = $self->_db_run_ex( $Class::User::DBI::DB::QUERY{SQL_list_users} );
    return $sth->fetchall_arrayref;
}

sub configure_db {
    my ( $class, $conn ) = @_;
    my @SQL_keys = qw(
      SQL_configure_db_users
      SQL_configure_db_user_ips
      SQL_configure_db_user_roles
    );
    foreach my $sql_key (@SQL_keys) {
        $conn->run(
            fixup => sub {
                $_->do( $Class::User::DBI::DB::QUERY{$sql_key} );
            }
        );
    }
    return 1;
}

1;

# Public API:
# my $user_obj = new( $connector, $userid )
#
# my $user_id  = $user->add_user(
#        {
#            password => $password,
#            ip_req   => $bool_ip_req,
#            ips      => [ '192.168.0.100', '201.202.100.5' ], # aref ip's.
#            username => $full_name,
#            email    => $email,
#        }
#    );
#
# my $userid      = $user->userid;
# my $validated   = $user->validated;
# my $invalidated = $user->validated(0);
# my $is_valid    = $user->validate_user( $pass, $opt_ips );
# my $info        = $user->load_user;
# my $valid_ips   = $user->fetch_valid_ips;
# my $user_exists = $user->exists_user;
# my $deleted     = $user->delete_user;
# my $del_count   = $user->delete_ips( [ @ips ] );
# my $add_count   = $user->add_ips( [ @ips ] );
# my $new_email   = $user->update_email( 'new@email.address' );
# my $new_name    = $user->update_username( 'Cool New User Name' );
# my $userid      = $user->update_password( 'Old Pass', 'New Pass' );
# my $users_aref  = $class->list_users;
# my $cans_aref   = $user->fetch_roles;
# my $success     = $user->add_role( $new_role );
# my $success     = $user->delete_role( $role );
# my $can_do      = $user->can_role( $role );

__END__

=head1 NAME

Class::User::DBI - A User class: Login credentials and roles.

=head1 VERSION

Version 0.01_001

=head1 SYNOPSIS

Through a DBIx::Connector object, this module models a "User" class, with
login credentials, and access roles.  Login credentials include a passphrase,
and optionally per user IP whitelisting.

Perhaps a little code snippet.

    use Class::User::DBI;

    my $foo = Class::User::DBI->new();
    ...


=head1 DESCRIPTION

The module is designed to simplify user logins, and basic administrative user
maintenance.  Passphrases are salted with a 512 bit random salt (unique per
user) using a cryptographically strong random number generator, and converted
to a SHA2-512 digest before being stored in the database.  All subsequent
passphrase validation checks test against the salt and passphrase SHA2 hash.

IP whitelists may be maintained per user.  If a user is set to require an IP
check, then the user validates only if his passphrase authenticates AND his
IP is found in the whitelist associated with his user id.

Users may be given zero or more roles.  Roles are simple strings, and may be
used by an authorization framework to determine what aspects of an
application's functionality will be available to a given user, or how the
functionality is presented.

To use: Instantiate a user object.  This user's initial state holds only a
userid.  Validate, load user info, load roles, test roles... read on.

=head1 EXPORT

Nothing is exported.  There are three class methods:

=over 4

=item * C<new()>

The constructor.

=item * C<list_users()>

Obtain a list of all users in the database.

=item * C<configure_db>

Build the tables for a minimal installation... C<IF NOT EXISTS>.

=back

=head1 SUBROUTINES/METHODS


=head2 	list_users

This is a class method.  Returns a reference to an array containing all
usernames.


=head2  configure_db


=head2 	new

# my $user_obj = new( $connector, $userid )


=head2 	fetch_user


=head2 	load_user


=head2 	delete_user


=head2 	exists_user


=head2 	add_user


=head2 	update_email


=head2 	update_password


=head2 	update_username


=head2 	userid


=head2 	validate_user


=head2 	validated




=head2 	fetch_valid_ips


=head2 	add_ips


=head2 	delete_ips



=head2 	fetch_roles

=head2 	can_role

=head2 	add_role

=head2 	delete_role


=head1 DEPENDENCIES

This module requires DBIx::Connector, and Authen::Passphrase::SaltedSHA512.
It also requires a database back-end.  The test suite will use DBD::SQLite,
but it has also been tested with DBD::mysql.  None of these dependencies could
be considered light-weight.  The dependency chain of this module is
indicative of the difficulty in assuring cryptographically strong random
salt generation, reliable SHA2-512 hashing of passphrases, fork-safe database
connectivity, and transactional commits for inserts and updates spanning
multiple tables.


=head1 CONFIGURATION AND ENVIRONMENT

The database used will need at least three User-related tables.  In their
simplest form, a minimal recommendation would be:


    TABLE:          users
    COLUMNS:        userid      VARCHAR(24)  NOT NULL DEFAULT ''
                    salt        CHAR(128)    NOT NULL DEFAULT ''
                    password    CHAR(128)    NOT NULL DEFAULT ''
                    ip_required tinyint(1)   NOT NULL DEFAULT '1'
                    username    VARCHAR(40)  DEFAULT NULL
                    email       VARCHAR(320) DEFAULT NULL
    PRIMARY KEY:    userid


    TABLE:          user_ips
    COLUMNS:        userid      VARCHAR(24)  NOT NULL DEFAULT ''
                    ip          INT(10) UNSIGNED NOT NULL DEFAULT '0'
    PRIMARY KEY:    userid, ip


    TABLE:          user_roles
    COLUMNS:        userid      VARCHAR(24) NOT NULL DEFAULT ''
                    role        VARCHAR(40) NOT NULL DEFAULT ''
    PRIMARY KEY:    userid, role

For convenience, configuration scripts are provided that will auto-generate
the minimal schema within a SQLite or MySQL database.  The SQLite database is
probably only useful for testing, as it lacks many of the security measures
present in web-stack-quality databases.  The configuration scripts are found
in the scripts/ directory within the distribution's build directory tree.


=head1 DIAGNOSTICS

=head1 INCOMPATIBILITIES

=head1 BUGS AND LIMITATIONS


=head1 AUTHOR


David Oswald, C<< <davido at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-class-user-dbi at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Class-User-DBI>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




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


=cut

1; # End of Class::User::DBI

## no critic (RCS,VERSION,POD)
package Class::User::DBI::DB;

use strict;
use warnings;
use 5.008;

use Exporter;
our @ISA       = qw( Exporter );     ## no critic (ISA)
our @EXPORT    = qw( db_run_ex );    ## no critic (export)
our @EXPORT_OK = qw(
  %USER_QUERY
  %PRIV_QUERY
  %DOM_QUERY
  %ROLE_QUERY
  %RP_QUERY
  _db_run_ex
);

use Carp;

our $VERSION = '0.01_003';
$VERSION = eval $VERSION;    ## no critic (eval)

# ---------------- SQL queries for Class::User::DBI --------------------------

our %USER_QUERY = (
    SQL_fetch_valid_ips => 'SELECT ip FROM user_ips WHERE userid = ?',
    SQL_fetch_credentials =>
      'SELECT salt, password, ip_required FROM users WHERE userid = ?',
    SQL_exists_user => 'SELECT userid FROM users WHERE userid = ?',
    SQL_load_profile =>
      'SELECT userid, username, email FROM users WHERE userid = ?',
    SQL_add_ips    => 'INSERT INTO user_ips ( userid, ip ) VALUES( ?, ? )',
    SQL_delete_ips => 'DELETE FROM user_ips WHERE userid = ? AND ip = ?',
    SQL_add_user => 'INSERT INTO users ( userid, salt, password, ip_required, '
      . 'username, email ) VALUES( ?, ?, ?, ?, ?, ? )',
    SQL_delete_user_users => 'DELETE FROM users WHERE userid = ?',
    SQL_delete_user_ips   => 'DELETE FROM user_ips WHERE userid = ?',
    SQL_delete_user_roles => 'DELETE FROM user_roles WHERE userid = ?',
    SQL_update_email      => 'UPDATE users SET email = ? WHERE userid = ?',
    SQL_update_username   => 'UPDATE users SET username = ? WHERE userid = ?',
    SQL_update_password =>
      'UPDATE users SET salt = ?, password = ? WHERE userid = ?',
    SQL_list_users  => 'SELECT userid, username, email FROM users',
    SQL_fetch_roles => 'SELECT role FROM user_roles WHERE userid = ?',
    SQL_can_role => 'SELECT role FROM user_roles WHERE userid = ? AND role = ?',
    SQL_add_roles => 'INSERT INTO user_roles ( userid, role ) VALUES ( ?, ? )',
    SQL_delete_roles => 'DELETE FROM user_roles WHERE userid = ? AND role = ?',
    SQL_configure_db_users => << 'END_SQL',
    CREATE TABLE IF NOT EXISTS users (
        userid      VARCHAR(24)           NOT NULL DEFAULT '',
        salt        CHAR(128)             DEFAULT NULL,
        password    CHAR(128)             DEFAULT NULL,
        ip_required TINYINT(1)            NOT NULL DEFAULT '1',
        username    VARCHAR(40)           DEFAULT NULL,
        email       VARCHAR(320)          DEFAULT NULL,
        role        varchar(24)           DEFAULT NULL,
        PRIMARY KEY( userid )
    )
END_SQL
    SQL_configure_db_user_ips => << 'END_SQL',
    CREATE TABLE IF NOT EXISTS user_ips (
        userid      VARCHAR(24)           NOT NULL DEFAULT '',
        ip          INT(10)               NOT NULL DEFAULT '0',
        PRIMARY KEY ( userid, ip )
    )
END_SQL
    SQL_configure_db_user_roles => << 'END_SQL',
    CREATE TABLE IF NOT EXISTS user_roles (
        userid      VARCHAR(24)           NOT NULL DEFAULT '',
        role        VARCHAR(40)           NOT NULL DEFAULT '',
        PRIMARY KEY ( userid, role )
    )
END_SQL
);

#------------ Queries for Class::User::DBI::Privileges -----------------------

our %PRIV_QUERY = (
    SQL_configure_db_cud_privileges => << 'END_SQL',
    CREATE TABLE IF NOT EXISTS cud_privileges (
        privilege   VARCHAR(24)           NOT NULL,
        description VARCHAR(40)           NOT NULL DEFAULT '',
        PRIMARY KEY (privilege)
    )
END_SQL
    SQL_exists_privilege =>
      'SELECT privilege FROM cud_privileges WHERE privilege = ?',
    SQL_add_privileges =>
      'INSERT INTO cud_privileges ( privilege, description ) VALUES ( ?, ? )',
    SQL_delete_privileges => 'DELETE FROM cud_privileges WHERE privilege = ?',
    SQL_get_privilege_description =>
      'SELECT description FROM cud_privileges WHERE privilege = ?',
    SQL_update_privilege_description =>
      'UPDATE cud_privileges SET description = ? WHERE privilege = ?',
    SQL_list_privileges => 'SELECT * FROM cud_privileges',
);

#----------------- Queries for Class::User::DBI::Domains ---------------------

our %DOM_QUERY = (
    SQL_configure_db_cud_domains => << 'END_SQL',
    CREATE TABLE IF NOT EXISTS cud_domains (
        domain      VARCHAR(24)           NOT NULL,
        description VARCHAR(40)           NOT NULL DEFAULT '',
        PRIMARY KEY (domain)
    )
END_SQL
    SQL_exists_domain => 'SELECT domain FROM cud_domains WHERE domain = ?',
    SQL_add_domains =>
      'INSERT INTO cud_domains ( domain, description ) VALUES ( ?, ? )',
    SQL_delete_domains => 'DELETE FROM cud_domains WHERE domain = ?',
    SQL_get_domain_description =>
      'SELECT description FROM cud_domains WHERE domain = ?',
    SQL_update_domain_description =>
      'UPDATE cud_domains SET description = ? WHERE domain = ?',
    SQL_list_domains => 'SELECT * FROM cud_domains',
);

#----------------- Queries for Class::User::DBI::Roles ---------------------

our %ROLE_QUERY = (
    SQL_configure_db_cud_roles => << 'END_SQL',
    CREATE TABLE IF NOT EXISTS cud_roles (
        role        VARCHAR(24)           NOT NULL,
        description VARCHAR(40)           NOT NULL DEFAULT '',
        PRIMARY KEY (role)
    )
END_SQL
    SQL_exists_role => 'SELECT role FROM cud_roles WHERE role = ?',
    SQL_add_roles =>
      'INSERT INTO cud_roles ( role, description ) VALUES ( ?, ? )',
    SQL_delete_roles => 'DELETE FROM cud_roles WHERE role = ?',
    SQL_get_role_description =>
      'SELECT description FROM cud_roles WHERE role = ?',
    SQL_update_role_description =>
      'UPDATE cud_roles SET description = ? WHERE role = ?',
    SQL_list_roles => 'SELECT * FROM cud_roles',
);

# ----------------- Queries for Class::User::DBI::RolePrivileges ------------

our %RP_QUERY = (
    SQL_configure_db_cud_roleprivs => << 'END_SQL',
    CREATE TABLE IF NOT EXISTS cud_roleprivs (
        role        VARCHAR(24)           NOT NULL DEFAULT '',
        privilege   VARCHAR(24)           NOT NULL DEFAULT '',
        PRIMARY KEY (role,privilege)
    )
END_SQL
    SQL_exists_priv =>
      'SELECT privilege FROM cud_roleprivs WHERE role = ? AND privilege = ?',
    SQL_add_priv =>
      'INSERT INTO cud_roleprivs ( role, privilege ) VALUES ( ?, ? )',
    SQL_delete_privileges =>
      'DELETE FROM cud_roleprivs WHERE role = ? AND privilege = ?',
    SQL_list_privileges => 'SELECT privilege FROM cud_roleprivs WHERE role = ?',
);

# ------------------------------ Functions -----------------------------------

# Prepares and executes a database command using DBIx::Connector's 'run'
# method.  Pass bind values as 2nd+ parameter(s).  If the first bind-value
# element is an array ref, bind value params will be executed in a loop,
# dereferencing each element's list upon execution:
# $self->_db_run_ex( 'SQL GOES HERE', @execute_params ); .... OR....
# $self->_db_run_ex(
#     'SQL GOES HERE',
#     [ first param list ], [ second param list ], ...
# );

sub db_run_ex {
    my ( $conn, $sql, @ex_params ) = @_;
    croak ref($conn) . ' is not a DBIx::Connector.'
      if !$conn->isa('DBIx::Connector');
    my $sth = $conn->run(
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

1;

__END__

=head1 SQL and other database-related data.
=cut

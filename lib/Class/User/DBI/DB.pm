## no critic (RCS,VERSION,POD)
package Class::User::DBI::DB;

use strict;
use warnings;
use 5.008;

use Exporter;
our @ISA       = qw ( Exporter );    ## no critic (ISA)
our @EXPORT_OK = qw( %QUERY );

our $VERSION = '0.01_001';
$VERSION = eval $VERSION;            ## no critic (eval)

# SQL queries used throughout Class::User::DBI.
our %QUERY = (
    SQL_fetch_valid_ips =>
      'SELECT INET_NTOA(ip) as ip FROM user_ips WHERE userid = ?',
    SQL_fetch_user =>
      'SELECT salt, password, ip_required FROM users WHERE userid = ?',
    SQL_exists_user => 'SELECT userid FROM users WHERE userid = ?',
    SQL_load_user =>
      'SELECT userid, username, email FROM users WHERE userid = ?',
    SQL_add_ips => 'INSERT INTO user_ips VALUES( ?, INET_ATON( ? ) )',
    SQL_delete_ips =>
      'DELETE FROM user_ips WHERE userid = ? AND ip = INET_ATON( ? )',
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
    SQL_add_role => 'INSERT INTO user_roles ( userid, role ) VALUES ( ?, ? )',
    SQL_delete_role => 'DELETE FROM user_roles WHERE userid = ? AND role = ?',
);

1;

=head1 SQL and other database-related data.
=cut

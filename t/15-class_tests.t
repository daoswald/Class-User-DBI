## no critic (RCS,VERSION,encapsulation,Module)

use strict;
use warnings;
use Test::More;
use Class::User::DBI;

# use Data::Dumper;

use DBIx::Connector;

# WARNING:  Tables will be dropped before and after running these tests.
#           Only run the tests against a test database containing no data
#           of value.
#           Tables 'users', 'user_ips', and 'user_roles' WILL be dropped.
# YOU HAVE BEEN WARNED.

# SQLite database settings.
my $dsn     = 'dbi:SQLite:dbname=:memory:';
my $db_user = q{};
my $db_pass = q{};

# mysql database settings.
# my $database = 'cudbi_test';
# my $dsn      = "dbi:mysql:database=$database";
# my $db_user  = 'tester';
# my $db_pass  = 'testers_pass';

my $conn = DBIx::Connector->new(
    $dsn, $db_user, $db_pass,
    {
        RaiseError => 1,
        AutoCommit => 1,
    }
);

my $appuser        = 'testuser';
my $appuser_ip_req = 'testuser_ip_req';
my $test_ip        = '192.168.0.198';
my $test_ip2       = '192.168.0.199';
my $appuser_pass   = 'Morerugs';

subtest 'Class::User::DBI use and can tests.' => sub {
    my $user = use_ok( 'Class::User::DBI', [ $conn, $appuser ] );
    can_ok(
        'Class::User::DBI', qw(
          new             add_user        userid          validated
          validate_user   load_user       fetch_valid_ips exists_user
          delete_user     delete_ips      add_ips         update_email
          update_username update_password list_users      fetch_roles
          add_role        delete_role     can_role
          )
    );
    done_testing();
};

# Prepare the database environment.
# Drop tables if they exist (in case we're testing against a non-memory
# test database.

$conn->run(
    fixup => sub {
        $_->do('DROP TABLE IF EXISTS users');
    }
);

$conn->run(
    fixup => sub {
        $_->do('DROP TABLE IF EXISTS user_ips');
    }
);

$conn->run(
    fixup => sub {
        $_->do('DROP TABLE IF EXISTS user_roles');
    }
);

Class::User::DBI->configure_db($conn);

subtest "Tests for $appuser" => sub {

    my $user = Class::User::DBI->new( $conn, $appuser );
    if ( !$user->exists_user ) {
        $user->add_user(
            {
                userid   => $appuser,
                password => $appuser_pass,
                email    => 'fake@address.com',
                username => 'Test User',
            }
        );
    }

    isa_ok( $user, 'Class::User::DBI', 'new():         ' );

    is( $user->userid, $appuser, 'userid():     Returns correct user ID.' );
    is( $user->validated, 0,
        'validated():    Returns false if user has not been validated yet.' );
    isa_ok( $user->_db_conn, 'DBIx::Connector', '_db_conn():     ' );

    my $query_handle = $user->_db_run_ex( 'SELECT * FROM users', () );
    isa_ok( $query_handle, 'DBI::st', '_db_run_ex():  ' );

    my $rv = $user->fetch_user();

    is( ref($rv), 'HASH', 'fetch_user():   Returns a hashref.' );
    ok( exists( $rv->{valid_ips} ),
        'fetch_user():   valid_ips   field found.' );
    ok( exists( $rv->{ip_required} ),
        'fetch_user():   ip_required field found.' );
    ok( exists( $rv->{salt_hex} ), 'fetch_user():   salt_hex    field found.' );
    ok( exists( $rv->{pass_hex} ), 'fetch_user():  pass_hex    field found.' );
    ok( exists( $rv->{userid} ),   'fetch_user():  userid    field found.' );
    is( $rv->{userid}, $appuser, 'fetch_user():  Correct userid found.' );
    is( ref( $rv->{valid_ips} ),
        'ARRAY', 'fetch_user():  valid_ips contains aref.' );
    is( $rv->{ip_required} == 0 || $rv->{ip_required} == 1,
        1, 'fetch_user():  ip_required is a Boolean value.' );
    like( $rv->{salt_hex}, qr/^[[:xdigit:]]{128}$/,
        'fetch_user():  salt_hex has 128 hex digits.' );
    like( $rv->{pass_hex}, qr/^[[:xdigit:]]{128}$/,
        'fetch_user():  pass_hex has 128 hex digits.' );
    is( scalar( @{ $user->fetch_valid_ips } ),
        0, "fetch_valid_ips():  $appuser has no IP's." );
    is( $user->exists_user, $appuser, "exists_user(): $appuser exists in DB." );
    is( $user->validate_user('wrong pass'),
        undef, 'validate_user: Reject incorrect password with undef.' );
    is( $user->validated, 0,
        'validated():   Flag still false after rejected validation.' );

    is( $user->validate_user($appuser_pass),
        $appuser, "validate_user(): $appuser validates by password." );
    is( $user->validated, 1,
            'validated():   Flag set to true after successful call '
          . 'to validate_user()' );
    $user->validated(0);
    is( $user->validated, 0,
        'validated():   User validation flag may be flipped to not-validated.'
    );
    $user->validated(1);
    is( $user->validated, 0,
            'validated():   User validation flag may not be explicitly set '
          . 'true via accessor.' );
    my $load = $user->load_user;
    is( ref($load), 'HASH', 'load_user(): Returns a hashref.' );
    is( $load->{userid}, $appuser,
        'load_userid()->{userid}: Returns proper user ID.' );
    like( $load->{email}, qr/@/,
            'load_userid()->{email}: Returns something that looks like an '
          . 'email address.' );
    done_testing();
};

subtest "Tests for $appuser_ip_req." => sub {
    my $user = Class::User::DBI->new( $conn, $appuser_ip_req );
    if ( !$user->exists_user ) {
        $user->add_user(
            {
                username => 'Test User Requiring IP',
                email    => 'fake@address.com',
                ip_req   => 1,
                ips      => ['192.168.0.198'],
                password => $appuser_pass,
            }
        );
    }
    isa_ok( $user, 'Class::User::DBI', 'new():         ' );
    is( grep( { $_ eq $test_ip } @{ $user->fetch_valid_ips } ),
        1, 'fetch_valid_ips(): Found a known IP in the DB.' );
    is( $user->validate_user($appuser_pass),
        undef,
        'validate_user(): Reject user requiring IP if no IP is supplied.' );
    is( $user->validate_user( $appuser_pass, '127.0.0.1' ),
        undef,
        'validate_user(): Reject user requiring IP if wrong IP is supplied.' );
    is(
        $user->validate_user( 'wrong pass', $test_ip ),
        undef,
        'validate_user(): Reject user requiring IP if incorrect pass '
          . 'with correct IP.'
    );
    is( $user->validate_user( $appuser_pass, $test_ip ),
        $appuser_ip_req,
        'validate_user(): Accept user if correct password and correct IP.' );

    my (@found) = grep { $_ eq $test_ip2 } @{ $user->fetch_valid_ips() };

    if (@found) {
        $user->delete_ips( [@found] );
    }

    is( grep( { $_ eq $test_ip2 } @{ $user->fetch_valid_ips() } ),
        0, "add_ips() test:  Initial state: $test_ip2 not in database." );
    $user->add_ips( [$test_ip2] );
    is( grep( { $_ eq $test_ip2 } @{ $user->fetch_valid_ips() } ),
        1, "add_ips() test:  $test_ip2 successfully added." );
    $user->delete_ips( [$test_ip2] );
    is( grep( { $_ eq $test_ip2 } @{ $user->fetch_valid_ips() } ),
        0, "delete_ips():    $test_ip2 successfully deleted." );

    done_testing();
};

subtest 'add_user() tests.' => sub {
    my $user = Class::User::DBI->new( $conn, 'saeed' );
    my $id = $user->add_user(
        {
            password => 'Super Me!',
            ip_req   => 1,
            ips      => [ '192.168.0.100', '201.202.100.5' ],
            username => 'Mr Incredible',
            email    => 'im@the.best',
        }
    );
    is(
        $user->add_ips( [ '192.168.0.100', '201.202.100.5', '127.0.0.1' ] ),
        1,
        'add_ips(): Gracefully drop ip adds for ips that are already '
          . 'in the DB.'
    );
    is( $id, 'saeed', 'add_user():  Properly returns the user id.' );
    is( defined( $user->exists_user ), 1, 'New user was added.' );
    is( $user->validate_user('Super Me!'),
        undef, 'New user fails to validate if ip_req set, and no IP given.' );
    is( $user->validate_user( 'Super Me!', '192.168.0.100' ),
        'saeed', 'New user validates.' );
    is( $user->delete_user, 1, 'delete_user(): Returns truth for success.' );
    is( scalar @{ $user->fetch_valid_ips },
        0, 'delete_user(): All IPs deleted for deleted user.' );
    is( $user->exists_user, undef,
        'exists_user(): Deleted user no longer exists in DB.' );
    is( $user->validated, 0,
        'validated(): deleted user is no longer validated.' );

    done_testing();
};

subtest 'User IDs should be forced to lower case.' => sub {
    my $user = Class::User::DBI->new( $conn, 'USER' );
    is( $user->userid, 'user', 'User id converted to lower case.' );

    done_testing();
};

subtest 'update_email() tests.' => sub {
    my $user      = Class::User::DBI->new( $conn, $appuser );
    my $stats_ref = $user->load_user;
    my $old_email = $stats_ref->{email};
    is( $old_email, 'fake@address.com',
        'load_user() found correct original email address.' );
    $user->update_email('newfake@address.com');
    $stats_ref = $user->load_user;
    my $new_email = $stats_ref->{email};
    is( $new_email, 'newfake@address.com', 'Email address correctly altered.' );
    $user->update_email($old_email);    # Reset to original state.
    $user = Class::User::DBI->new( $conn, 'Invalid user' );
    is( $user->update_email('testing@test.test'),
        undef, 'Correctly rejects updates on invalid users.' );
    done_testing();
};

subtest 'update_username() tests.' => sub {
    my $user      = Class::User::DBI->new( $conn, $appuser );
    my $stats_ref = $user->load_user;
    my $old_name  = $stats_ref->{username};
    is( $old_name, 'Test User', 'load_user() found correct user name.' );
    $user->update_username('Cool Test User');
    $stats_ref = $user->load_user;
    my $new_name = $stats_ref->{username};
    is( $new_name, 'Cool Test User', 'update_username() set a new user name.' );
    $user->update_username($old_name);
    $user = Class::User::DBI->new( $conn, 'Invalid user' );
    is( $user->update_username('Bogus User'),
        undef, 'Correctly rejects updates on invalid users.' );
    done_testing();
};

subtest 'update_password() tests.' => sub {
    my $user = Class::User::DBI->new( $conn, 'passupdate_user' );
    my $userid = $user->add_user(
        {
            password => 'Pass1',
            ip_req   => 0,
            username => 'Password Updating User',
            email    => 'email@address.com',
        }
    );
    is( $user->validate_user('Pass1'),
        'passupdate_user', 'New user validates.' );
    is( $user->update_password( 'Pass1', 'Pass2' ),
        'passupdate_user', 'Pass updated.' );
    my $user2 = Class::User::DBI->new( $conn, 'passupdate_user' );
    is( $user2->validate_user('Pass2'),
        'passupdate_user', 'User validates against new passphrase.' );
    $user2->delete_user;
    done_testing;
};

subtest 'list_users() tests.' => sub {
    my $user_aref = Class::User::DBI->list_users($conn);
    is( ref($user_aref), 'ARRAY',
        'Class::User::DBI->list_users() returns an arrayref.' );
    is( scalar( grep { $_->[0] eq $appuser } @{$user_aref} ),
        1, 'Found our test user.' );
    is( scalar @{$user_aref} > 1, 1, 'Found more than one user.' );
    done_testing();
};

subtest 'Roles tests.' => sub {
    my $user = Class::User::DBI->new( $conn, $appuser );
    if ( !$user->can_role('tupitar') ) {
        $user->add_role('tupitar');
    }
    my $roles_aref = $user->fetch_roles;
    is( ref $roles_aref, 'ARRAY', 'fetch_roles() returns an arrayref.' );
    is( scalar( grep { $_ eq 'tupitar' } @{$roles_aref} ),
        1, 'fetch_roles(): tupitar is a role.' );
    ok( $user->can_role('tupitar'), 'can_role(): Test user can tupitar.' );
    ok( !$user->can_role('frobcinate'),
        'can_role(): Test user can not frobcinate (yet).' );
    is( $user->add_role('frobcinate'),
        'frobcinate', 'add_role(): Added frobcinate role.' );
    ok( $user->can_role('frobcinate'),
        'can_role(): Test user can now frobcinate.' );
    ok(
        $user->delete_role('frobcinate'),
        'delete_role(): Deleted frobcinate role.'
    );
    ok( !$user->can_role('frobcinate'),
        'can_role(): Test user can no longer frobcinate.' );
    my $user2 = Class::User::DBI->new( $conn, 'roles_user' );
    $user2->add_user(
        {
            password => 'something',
            username => 'somebody',
            email    => 'this@that.com'
        }
    );
    $user2->add_role('frobcinate');
    $user2->delete_user;
    ok( !$user2->can_role('frobcinate'),
        'delete_user: Deleted user can no longer frobcinate.' );
    done_testing();
};

done_testing();

__END__



TODO:

Set up the tests to create the test users initially, and clean up afterward.
Set up the DB to accept a 'tester' user, and convert testing to tester user.
Split up modules and tests.
Figure out how to install the module in the application directory tree.
User::Credentials::Provider::DBI


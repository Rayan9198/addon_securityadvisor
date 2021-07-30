#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright (c) 2019, cPanel, L.L.C.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL cPanel, L.L.C. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../pkg";

use Test::More;
use Test::Deep;
use Test::MockModule;
use IO::Pty;

use Test::Assessor;

use Cpanel::Version ();

plan skip_all => 'Requires cPanel & WHM v66 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.65' );
plan tests    => 4;

use Cpanel::Security::Advisor::Assessors::Mysql ();

my $mock_connect = Test::MockModule->new('Cpanel::MysqlUtils::Connect');
$mock_connect->redefine( 'connect', sub { } );

local $ENV{'REQUEST_URI'} = '';    # for the URL that is returned by base_path

# Avoid maketext failures related to html vs. text context when non-interactive
my $pty = IO::Pty->new();
local *STDIN = $pty->slave;

subtest 'Check if Mysql can connect' => sub {
    plan tests => 1;

    my $mock_object = Test::MockModule->new('Cpanel::Security::Advisor::Assessors::Mysql');
    $mock_object->redefine(
        '_check_for_db_test'             => sub { return 1 },
        '_check_for_anonymous_users'     => sub { return 1 },
        '_check_for_public_bind_address' => sub { return 1 },
        '_sqlcmd'                        => sub { return 0; },
    );

    my $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
        function => ignore(),
        advice   => {
            key        => 'Mysql_can_not_connect_to_mysql',
            text       => 'Cannot connect to MySQL server.',
            type       => $Cpanel::Security::Advisor::ADVISE_BAD,
            suggestion => 'Enable the MySQL database service (../scripts/srvmng).',
        },
    };
    cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when it cannot connect to mysql properly' );
};

subtest 'Check for db test' => sub {
    plan tests => 2;

    my $mock_object = Test::MockModule->new('Cpanel::Security::Advisor::Assessors::Mysql');
    $mock_object->redefine(
        '_check_for_anonymous_users'     => sub { return 1 },
        '_check_for_public_bind_address' => sub { return 1 },
        '_sqlcmd'                        => sub {
            my ( $self, $cmd ) = @_;
            return 0 if $cmd eq "show databases like 'test'";
            return 1;
        },
    );

    my $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
        function => ignore(),
        advice   => {
            key  => 'Mysql_test_database_does_not_exist',
            text => 'MySQL test database does not exist.',
            type => $Cpanel::Security::Advisor::ADVISE_GOOD,
        },
    };
    cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when the test database does not exist' );

    $mock_object->redefine( '_sqlcmd' => sub { return 1; } );
    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
        function => ignore(),
        advice   => {
            key        => 'Mysql_test_database_exists',
            text       => 'MySQL test database exists.',
            type       => $Cpanel::Security::Advisor::ADVISE_BAD,
            suggestion => q{Numerous attacks exploit the MySQL test database. To remove it, run “mysql -e 'drop database test'”.}
        },
    };
    cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when the test database exists' );
};

subtest 'Check for anonymous users' => sub {
    plan tests => 2;

    my $hostname_mock = Test::MockModule->new('Cpanel::Hostname');
    $hostname_mock->redefine( 'gethostname' => 'benderisgreat.com' );

    my $mock_object = Test::MockModule->new('Cpanel::Security::Advisor::Assessors::Mysql');
    $mock_object->redefine(
        '_check_for_db_test'             => sub { return 1 },
        '_check_for_public_bind_address' => sub { return 1 },
        '_sqlcmd'                        => sub {
            my ( $self, $cmd ) = @_;
            return 1 if $cmd eq "SELECT 1;";
            return 0;
        },
    );

    my $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
        function => ignore(),
        advice   => {
            key  => 'Mysql_no_anonymous_users',
            text => 'MySQL check for anonymous users',
            type => $Cpanel::Security::Advisor::ADVISE_GOOD,
        },
    };
    cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when there are no anonymous users' );

    $mock_object->redefine( '_sqlcmd' => sub { return 1 } );
    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
        function => ignore(),
        advice   => {
            key        => 'Mysql_found_anonymous_users',
            text       => 'You have some anonymous MySQL users',
            type       => $Cpanel::Security::Advisor::ADVISE_BAD,
            suggestion => q{Remove MySQL anonymous MySQL users: mysql -e "DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;"}
        },
    };
    cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when there are anonymous users' );
};

subtest 'Check for a public bind address' => sub {
    plan tests => 5;

    my $mock_object = Test::MockModule->new('Cpanel::Security::Advisor::Assessors::Mysql');
    $mock_object->redefine(
        '_check_for_db_test'         => sub { return 1 },
        '_check_for_anonymous_users' => sub { return 1 },
        '_sqlcmd'                    => sub { return 1 },
    );

    my $mycnf_mock = Test::MockModule->new('Cpanel::MysqlUtils::MyCnf::Full');
    $mycnf_mock->redefine(
        'etc_my_cnf' => sub {
            return {
                'mysqld' => {
                    'bind-address' => '127.0.0.1',
                    'port'         => '3306',
                },
            };
        }
    );

    my $saferun_mock = Test::MockModule->new('Cpanel::SafeRun::Errors');
    $saferun_mock->redefine( 'saferunnoerror' => sub { return ('bender') } );

    my $ipparse_mock = Test::MockModule->new('Cpanel::IP::Parse');
    $ipparse_mock->redefine( 'parse' => (1) );

    my $loopback_mock = Test::MockModule->new('Cpanel::IP::Loopback');

    subtest 'where the bind address is a loopback address' => sub {
        $loopback_mock->redefine( 'is_loopback' => 1 );

        my $expected = {
            module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
            function => ignore(),
            advice   => {
                key  => 'Mysql_listening_only_to_local_address',
                text => 'MySQL is listening only on a local address.',
                type => $Cpanel::Security::Advisor::ADVISE_GOOD,
            },
        };
        cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when the bind address is a loopback address' );
    };

    $loopback_mock->redefine( 'is_loopback' => 0 );

    subtest 'where the port is blocked by firewall 1' => sub {
        $ipparse_mock->redefine( 'parse'          => (4) );
        $saferun_mock->redefine( 'saferunnoerror' => sub { return ('--dport 3306 -j REJECT') } );
        $mycnf_mock->redefine(
            'etc_my_cnf' => sub {
                return {
                    'mysqld' => {
                        'bind-address' => 'ffff',
                        'port'         => '3306',
                    },
                };
            }
        );
        my $expected = {
            module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
            function => ignore(),
            advice   => {
                key  => 'Mysql_port_blocked_by_firewall_1',
                text => 'The MySQL port is blocked by the firewall, effectively allowing only local connections.',
                type => $Cpanel::Security::Advisor::ADVISE_GOOD,
            },
        };
        cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when the bind address port is blocked by firewall 1' );
    };

    subtest 'where the port is listening on a public address' => sub {
        $ipparse_mock->redefine( 'parse'          => (4) );
        $saferun_mock->redefine( 'saferunnoerror' => sub { return ('') } );
        $mycnf_mock->redefine(
            'etc_my_cnf' => sub {
                return {
                    'mysqld' => {
                        'bind-address' => 'ffff',
                        'port'         => '3306',
                    },
                };
            }
        );
        my $expected = {
            module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
            function => ignore(),
            advice   => {
                key        => 'Mysql_listening_on_public_address',
                text       => 'The MySQL service is currently configured to listen on a public address: (bind-address=ffff)',
                suggestion => 'Configure bind-address=127.0.0.1 in /etc/my.cnf, or close port 3306 in the server’s firewall.',
                type       => $Cpanel::Security::Advisor::ADVISE_BAD,
            },
        };
        cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when the bind address port is listening on a public address' );
    };

    subtest 'where the bind address is empty and the port has deny rules for IPv6' => sub {
        $ipparse_mock->redefine( 'parse' => (6) );
        $saferun_mock->redefine(
            'saferunnoerror' => sub {
                return ('--dport 3306 -j REJECT');
            }
        );
        $mycnf_mock->redefine(
            'etc_my_cnf' => sub {
                return {
                    'mysqld' => {
                        'bind-address' => undef,
                        'port'         => '3306',
                    },
                };
            }
        );
        my $expected = {
            module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
            function => ignore(),
            advice   => {
                key  => 'Mysql_port_blocked_by_firewall_2',
                text => 'The MySQL port is blocked by the firewall, effectively allowing only local connections.',
                type => $Cpanel::Security::Advisor::ADVISE_GOOD,
            },
        };
        cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when the bind address is undefined but the port is blocked on IPv6' );
    };

    subtest 'where the bind address is empty and the port is not blocked' => sub {
        $ipparse_mock->redefine( 'parse'          => (4) );
        $saferun_mock->redefine( 'saferunnoerror' => sub { return (''); } );
        $mycnf_mock->redefine(
            'etc_my_cnf' => sub {
                return {
                    'mysqld' => {
                        'bind-address' => undef,
                        'port'         => '3306',
                    },
                };
            }
        );
        my $expected = {
            module   => 'Cpanel::Security::Advisor::Assessors::Mysql',
            function => ignore(),
            advice   => {
                key        => 'Mysql_listening_on_all_interfaces',
                text       => 'The MySQL service is currently configured to listen on all interfaces: (bind-address=*)',
                suggestion => 'Configure bind-address=127.0.0.1 in /etc/my.cnf, or close port 3306 in the server’s firewall.',
                type       => $Cpanel::Security::Advisor::ADVISE_BAD,
            },
        };
        cmp_assessor( 'Mysql', [$expected], 'generate_advice detects when the bind address is undefined and the port is not blocked' );
    };
};

sub cmp_assessor {
    my ( $assessor, $expected, $msg ) = @_;

    local $Test::Builder::Level = $Test::Builder::Level + 1;

    my $object = Test::Assessor->new( assessor => $assessor );
    $object->generate_advice();

    my $got = $object->get_advice();
    $object->clear_advice();

    my $ret = cmp_deeply( $got, $expected, $msg );
    diag explain $got if !$ret;

    return $ret;
}


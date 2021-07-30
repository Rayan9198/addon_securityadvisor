#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright (c) 2017, cPanel, Inc.
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
use lib "$FindBin::Bin/lib", "$FindBin::Bin/../../pkg";

use Test::More;
use Test::Deep;
use Test::MockModule;
use IO::Pty;

use Test::Assessor ();

use Cpanel::Exception ();
use Cpanel::Version   ();

plan skip_all => 'Requires cPanel & WHM v66 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.65' );
plan tests    => 6;

# Suppress warnings related to checking this path, and create relative paths that are realistic
local $ENV{REQUEST_URI} = '/cpsessXXXXXXX/cgi/securityadvisor/index.cgi';

# Avoid maketext failures related to html vs. text context when non-interactive
my $pty = IO::Pty->new();
local *STDIN = $pty->slave;

subtest 'Missing executable' => sub {
    plan tests => 1;

    my $outdated = Test::MockModule->new('Cpanel::ProcessCheck::Outdated');
    my $err      = sub { die Cpanel::Exception::create( 'Service::BinaryNotFound', [ service => 'needs-restarting' ] ) };
    $outdated->mock(
        reboot_suggested   => $err,
        outdated_services  => $err,
        outdated_processes => $err,
    );

    my $expected = {
        key        => 'Processes_unable_to_check_running_executables',
        text       => 'Unable to check whether running executables are up-to-date.',
        suggestion => 'Install the ‘needs-restarting’ command to check if processes are up-to-date.',
        type       => $Cpanel::Security::Advisor::ADVISE_INFO,
    };
    cmp_assessor( 'Processes', [$expected], 'Error displayed' );
};

subtest 'Handle unexpected error' => sub {
    plan tests => 6;

    my $outdated = Test::MockModule->new('Cpanel::ProcessCheck::Outdated');
    my $err      = sub { die "Simple string\n" };
    $outdated->mock(
        reboot_suggested   => sub { },
        outdated_services  => sub { },
        outdated_processes => $err,
    );

    my @expected;
    unshift @expected, {
        key  => 'Processes_error_while_checking_running_executables',
        text => "Failed to check whether running executables are up-to-date: Simple string\n",
        type => $Cpanel::Security::Advisor::ADVISE_WARN,
    };
    cmp_assessor( 'Processes', \@expected, 'Warning displayed for plain error on outdated processes' );

    $outdated->mock( outdated_services => $err );
    unshift @expected, {
        key  => 'Processes_error_while_checking_running_services',
        text => "Failed to check whether active services are up-to-date: Simple string\n",
        type => $Cpanel::Security::Advisor::ADVISE_WARN,
    };
    cmp_assessor( 'Processes', \@expected, 'Warning displayed for plain error on outdated services' );

    $outdated->mock( reboot_suggested => $err );
    unshift @expected, {
        key  => 'Processes_error_while_checking_reboot',
        text => "Failed to determine if a reboot is necessary: Simple string\n",
        type => $Cpanel::Security::Advisor::ADVISE_WARN,
    };
    cmp_assessor( 'Processes', \@expected, 'Warning displayed for plain error on reboot suggestion' );

    $err = sub { die Cpanel::Exception->create('Cpanel::Exception object') };
    $outdated->mock(
        reboot_suggested   => sub { },
        outdated_services  => sub { },
        outdated_processes => $err,
    );

    @expected = ();
    unshift @expected, {
        key  => 'Processes_error_while_checking_running_executables',
        text => 'Failed to check whether running executables are up-to-date: Cpanel::Exception object',
        type => $Cpanel::Security::Advisor::ADVISE_WARN,
    };
    cmp_assessor( 'Processes', \@expected, 'Warning displayed for blessed error on outdated processes' );

    $outdated->mock( outdated_services => $err );
    unshift @expected, {
        key  => 'Processes_error_while_checking_running_services',
        text => 'Failed to check whether active services are up-to-date: Cpanel::Exception object',
        type => $Cpanel::Security::Advisor::ADVISE_WARN,
    };
    cmp_assessor( 'Processes', \@expected, 'Warning displayed for blessed error on outdated services' );

    $outdated->mock( reboot_suggested => $err );
    unshift @expected, {
        key  => 'Processes_error_while_checking_reboot',
        text => 'Failed to determine if a reboot is necessary: Cpanel::Exception object',
        type => $Cpanel::Security::Advisor::ADVISE_WARN,
    };
    cmp_assessor( 'Processes', \@expected, 'Warning displayed for blessed error on reboot suggestion' );
};

subtest 'Handle unsupported systems' => sub {
    plan tests => 2;

    my $outdated = Test::MockModule->new('Cpanel::ProcessCheck::Outdated');
    my $err      = sub { die Cpanel::Exception::create( 'Unsupported', 'The kernel does not support [asis,smaps].' ) };
    $outdated->mock(
        reboot_suggested   => $err,
        outdated_services  => $err,
        outdated_processes => $err,
    );

    cmp_assessor( 'Processes', [], 'No recommendations given' );

    $err = sub { die Cpanel::Exception::create( 'Unsupported', 'Not supported by “[_1]” before [asis,CentOS 7].', ['needs-restarting'] ) };
    $outdated->mock(
        reboot_suggested   => $err,
        outdated_services  => $err,
        outdated_processes => sub { },
    );

    my $expected = {
        key  => 'Processes_none_with_outdated_executables',
        text => 'The system did not detect processes with outdated binaries.',
        type => $Cpanel::Security::Advisor::ADVISE_GOOD,
    };
    cmp_assessor( 'Processes', [$expected], 'Good status displayed' );
};

subtest 'Recommend reboot' => sub {
    plan tests => 3;

    my $outdated = Test::MockModule->new('Cpanel::ProcessCheck::Outdated');
    $outdated->mock(
        reboot_suggested   => sub { { systemd => '219-30.el7_3.7' } },
        outdated_services  => sub { },
        outdated_processes => sub { },
    );

    my $expected = {
        key        => 'Processes_detected_running_from_outdated_executables',
        text       => 'The system’s core libraries or services have been updated.',
        suggestion => 'Reboot the server (../../scripts/dialog?dialog=reboot) to ensure the system benefits from these updates.',
        type       => $Cpanel::Security::Advisor::ADVISE_BAD,
    };
    cmp_assessor( 'Processes', [$expected], 'Core libraries updated' );

    $outdated->mock(
        outdated_services  => sub { qw(exim.service cpanellogd.service) },
        outdated_processes => sub { ( 2, 703, 5840 ) },
    );

    # $expected unchanged
    cmp_assessor( 'Processes', [$expected], 'Core libraries updated - other things too' );

    $outdated->mock(
        reboot_suggested   => sub { },
        outdated_services  => sub { },
        outdated_processes => sub { (1) },
    );

    $expected = {
        key        => 'Processes_detected_running_outdated_executables',
        text       => 'Detected 1 process that is running outdated executables: 1',
        suggestion => 'Reboot the server (../../scripts/dialog?dialog=reboot) to ensure the system benefits from these updates.',
        type       => $Cpanel::Security::Advisor::ADVISE_BAD,
    };
    cmp_assessor( 'Processes', [$expected], 'PID 1 updated' );
};

subtest 'Recommend process restart' => sub {
    plan tests => 3;

    my $outdated = Test::MockModule->new('Cpanel::ProcessCheck::Outdated');
    $outdated->mock(
        reboot_suggested   => sub { },
        outdated_services  => sub { ( 'foo.service', 'bar.service' ) },
        outdated_processes => sub { },
    );

    my $expected = {
        key        => 'Processes_detected_running_outdated_services',
        text       => 'Detected 2 services that are running outdated executables: foo.service bar.service',
        suggestion => 'You must take one of the following actions to ensure the system is up-to-date:<ul><li>Restart the listed services using “systemctl restart foo.service bar.service”; then click “Scan Again” to check non-service processes.</li><li>Reboot the server (../../scripts/dialog?dialog=reboot).</li></ul>',
        type       => $Cpanel::Security::Advisor::ADVISE_BAD,
    };
    cmp_assessor( 'Processes', [$expected], 'One process outdated' );

    $outdated->mock(
        reboot_suggested   => sub { },
        outdated_services  => sub { },
        outdated_processes => sub { (42) },
    );

    $expected = {
        key        => 'Processes_detected_running_outdated_executables',
        text       => 'Detected 1 process that is running outdated executables: 42',
        suggestion => 'You must take one of the following actions to ensure the system is up-to-date:<ul><li>Restart the listed process.</li><li>Reboot the server (../../scripts/dialog?dialog=reboot).</li></ul>',
        type       => $Cpanel::Security::Advisor::ADVISE_BAD,
    };
    cmp_assessor( 'Processes', [$expected], 'One process outdated' );

    $outdated->mock(
        outdated_processes => sub { ( 42, 1337, 2017, 9374, 31337 ) },
    );
    $expected = {
        key        => 'Processes_detected_running_outdated_executables',
        text       => 'Detected 5 processes that are running outdated executables: 42 1337 2017 9374 31337',
        suggestion => 'You must take one of the following actions to ensure the system is up-to-date:<ul><li>Restart the listed processes.</li><li>Reboot the server (../../scripts/dialog?dialog=reboot).</li></ul>',
        type       => $Cpanel::Security::Advisor::ADVISE_BAD,
    };
    cmp_assessor( 'Processes', [$expected], 'Multiple processes outdated' );
};

subtest 'Status good' => sub {
    plan tests => 1;

    my $outdated = Test::MockModule->new('Cpanel::ProcessCheck::Outdated');
    $outdated->mock(
        reboot_suggested   => sub { },
        outdated_services  => sub { },
        outdated_processes => sub { },
    );

    my $expected = {
        key  => 'Processes_none_with_outdated_executables',
        text => 'The system did not detect processes with outdated binaries.',
        type => $Cpanel::Security::Advisor::ADVISE_GOOD,
    };
    cmp_assessor( 'Processes', [$expected], 'Good status displayed' );
};

sub cmp_assessor {
    my ( $assessor, $expected_advice, $msg ) = @_;

    local $Test::Builder::Level = $Test::Builder::Level + 1;

    my $object = Test::Assessor->new( assessor => $assessor );
    $object->generate_advice();

    my $got = $object->get_advice();
    $object->clear_advice();

    my @expected = map { { module => "Cpanel::Security::Advisor::Assessors::$assessor", function => ignore(), advice => $_ } } @$expected_advice;

    my $ret = cmp_deeply( $got, \@expected, $msg );
    diag explain $got if !$ret;

    return $ret;
}

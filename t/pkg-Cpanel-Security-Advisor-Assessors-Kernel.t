#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright (c) 2018, cPanel, Inc.
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

use Test::Assessor ();

use Cpanel::Exception ();
use Cpanel::Version   ();

plan skip_all => 'Requires cPanel & WHM v66 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.65' );
plan tests    => 4;

my $envtype = Test::MockModule->new('Cpanel::KernelCare');
$envtype->mock( system_supports_kernelcare => sub { 0 } );    # Disable KernelCare advertisements.

local $ENV{'REQUEST_URI'} = 'mocking out to avoid warnings';

# Avoid maketext failures related to html vs. text context when non-interactive
my $pty = IO::Pty->new();
local *STDIN = $pty->slave;

subtest 'Error parsing boot configuration' => sub {
    plan tests => 2;

    my $status = Test::MockModule->new('Cpanel::Kernel::Status');
    $status->mock( kernel_status => sub { die Cpanel::Exception->create('Cannot determine startup kernel version.') } );

    my $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_check_error',
            text => 'The system cannot check the kernel status: Cannot determine startup kernel version.',
            type => $Cpanel::Security::Advisor::ADVISE_WARN,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Handle empty return errors' );

    $status->mock( kernel_status => sub { die "Unable to locate grub2-editenv binary. You may need to re-install grub2-tools package.\n" } );
    $expected->{advice}{text} = "The system cannot check the kernel status: Unable to locate grub2-editenv binary. You may need to re-install grub2-tools package.\n";
    cmp_assessor( 'Kernel', [$expected], 'Handle string errors' );
};

subtest 'Custom kernels' => sub {
    plan tests => 2;

    my %status = (
        custom_kernel   => 1,
        running_version => '3.10.0-514.el7.x86_64.grsec',
        boot_version    => '3.10.0-514.el7.x86_64.grsec',
        reboot_required => 0,
    );
    my $status = Test::MockModule->new('Cpanel::Kernel::Status');
    $status->mock( kernel_status => sub { \%status } );

    my $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_can_not_check',
            text => 'Custom kernel version cannot be checked to see if it is up to date: 3.10.0-514.el7.x86_64.grsec',
            type => $Cpanel::Security::Advisor::ADVISE_INFO,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Boot and running version match' );

    # Mismatch boot & running versions.
    $status{boot_version}    = '3.10.0-514.6.2.el7.x86_64.grsec';
    $status{reboot_required} = 1;

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key        => 'Kernel_boot_running_mismatch',
            text       => 'The system kernel is at version “3.10.0-514.el7.x86_64.grsec”, but the system is configured to boot version “3.10.0-514.6.2.el7.x86_64.grsec”.',
            suggestion => 'Reboot the system (../scripts/dialog?dialog=reboot). If the problem persists, check the GRUB boot configuration.',
            type       => $Cpanel::Security::Advisor::ADVISE_WARN,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Boot and running version mismatch' );
};

subtest 'Standard kernel' => sub {
    plan tests => 5;

    my %status = (
        has_kernelcare   => 0,
        running_version  => '3.10.0-514.el7.x86_64',
        boot_version     => '3.10.0-514.el7.x86_64',
        reboot_required  => 0,
        update_available => undef,
        running_latest   => 1,
    );
    my $status = Test::MockModule->new('Cpanel::Kernel::Status');
    $status->mock( kernel_status => sub { \%status } );

    my $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_running_is_current',
            text => 'The system kernel is up-to-date at version “3.10.0-514.el7.x86_64”.',
            type => $Cpanel::Security::Advisor::ADVISE_GOOD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Up to date system' );

    %status = (
        has_kernelcare   => 0,
        running_version  => '3.10.0-514.el7.x86_64',
        boot_version     => '3.10.0-514.6.2.el7.x86_64',
        reboot_required  => 1,
        update_available => undef,
        running_latest   => 0,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key        => 'Kernel_boot_running_mismatch',
            text       => 'The system kernel is at version “3.10.0-514.el7.x86_64”, but the system is configured to boot version “3.10.0-514.6.2.el7.x86_64”.',
            suggestion => 'Reboot the system (../scripts/dialog?dialog=reboot). If the problem persists, check the GRUB boot configuration.',
            type       => $Cpanel::Security::Advisor::ADVISE_BAD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Boot and running version mismatch' );

    %status = (
        has_kernelcare   => 0,
        running_version  => '3.10.0-514.el7.x86_64',
        boot_version     => '3.10.0-514.el7.x86_64',
        reboot_required  => 0,
        update_available => {
            rpm     => 'kernel-3.10.0-514.10.2.el7.x86_64',
            name    => 'kernel',
            version => '3.10.0',
            release => '514.10.2.el7',
            arch    => 'x86_64',
        },
        running_latest => 0,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key        => 'Kernel_outdated',
            text       => 'The system kernel is at version “3.10.0-514.el7.x86_64”, but an update is available: 3.10.0-514.10.2.el7.x86_64',
            suggestion => 'Update the system (run “yum -y update” on the command line), and reboot the system (../scripts/dialog?dialog=reboot).',
            type       => $Cpanel::Security::Advisor::ADVISE_BAD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Update available' );

    $status{update_excluded} = 1;

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_running_is_current',
            text => 'The system kernel is up-to-date at version “3.10.0-514.el7.x86_64”.',
            type => $Cpanel::Security::Advisor::ADVISE_GOOD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Update available, but excluded' );

    %status = (
        has_kernelcare   => 0,
        running_version  => '3.10.0-514.el7.x86_64',
        boot_version     => '3.10.0-514.6.2.el7.x86_64',
        reboot_required  => 1,
        update_available => {
            rpm     => 'kernel-3.10.0-514.10.2.el7.x86_64',
            name    => 'kernel',
            version => '3.10.0',
            release => '514.10.2.el7',
            arch    => 'x86_64',
        },
        running_latest => 0,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key        => 'Kernel_outdated',
            text       => 'The system kernel is at version “3.10.0-514.el7.x86_64”, but an update is available: 3.10.0-514.10.2.el7.x86_64',
            suggestion => 'Update the system (run “yum -y update” on the command line), and reboot the system (../scripts/dialog?dialog=reboot).',
            type       => $Cpanel::Security::Advisor::ADVISE_BAD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Update available & boot and running version mismatch' );
};

subtest 'KernelCare systems' => sub {
    plan tests => 12;

    my %status = (
        has_kernelcare    => 1,
        unpatched_version => '3.10.0-514.el7.x86_64',
        running_version   => '3.10.0-514.el7.x86_64',
        boot_version      => '3.10.0-514.el7.x86_64',
        reboot_required   => 0,
        update_available  => undef,
        patch_available   => 0,
        running_latest    => 1,
    );
    my $status = Test::MockModule->new('Cpanel::Kernel::Status');
    $status->mock( kernel_status => sub { \%status } );

    my $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_kernelcare_is_current',
            text => 'KernelCare is installed and current running kernel version is up to date: 3.10.0-514.el7.x86_64',
            type => $Cpanel::Security::Advisor::ADVISE_GOOD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Up to date system' );

    %status = (
        has_kernelcare    => 1,
        unpatched_version => '3.10.0-514.el7.x86_64',
        running_version   => '3.10.0-514.el7.x86_64',
        boot_version      => '3.10.0-514.6.2.el7.x86_64',
        reboot_required   => 1,
        update_available  => undef,
        patch_available   => 0,
        running_latest    => 0,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_waiting_for_kernelcare_update_2',
            text => 'The system kernel has changed from version “3.10.0-514.el7.x86_64” to boot to version “3.10.0-514.6.2.el7.x86_64”. While you are fully protected by KernelCare, it may still be a good idea to reboot into the latest system kernel at your earliest convenience.',
            type => $Cpanel::Security::Advisor::ADVISE_INFO,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Boot and running version mismatch' );

    %status = (
        has_kernelcare    => 1,
        unpatched_version => '3.10.0-514.el7.x86_64',
        running_version   => '3.10.0-514.el7.x86_64',
        boot_version      => '3.10.0-514.el7.x86_64',
        reboot_required   => 0,
        update_available  => {
            rpm     => 'kernel-3.10.0-514.10.2.el7.x86_64',
            name    => 'kernel',
            version => '3.10.0',
            release => '514.10.2.el7',
            arch    => 'x86_64',
        },
        patch_available => 0,
        running_latest  => 0,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key        => 'Kernel_waiting_for_kernelcare_update',
            text       => 'The system kernel is at version “3.10.0-514.el7.x86_64”, but an update is available: 3.10.0-514.10.2.el7.x86_64',
            suggestion => 'You must take one of the following actions to ensure the system is up-to-date:<ul><li>Wait a few days for KernelCare to publish a kernel patch.</li><li>Update the system (run “yum -y update” on the command line), and reboot the system (../scripts/dialog?dialog=reboot).</li></ul>',
            type       => $Cpanel::Security::Advisor::ADVISE_INFO,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Update available' );

    $status{update_excluded} = 1;

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_kernelcare_is_current',
            text => 'KernelCare is installed and current running kernel version is up to date: 3.10.0-514.el7.x86_64',
            type => $Cpanel::Security::Advisor::ADVISE_GOOD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Update available, but excluded' );

    %status = (
        has_kernelcare    => 1,
        unpatched_version => '3.10.0-514.el7.x86_64',
        running_version   => '3.10.0-514.el7.x86_64',
        boot_version      => '3.10.0-514.6.2.el7.x86_64',
        reboot_required   => 1,
        update_available  => {
            rpm     => 'kernel-3.10.0-514.10.2.el7.x86_64',
            name    => 'kernel',
            version => '3.10.0',
            release => '514.10.2.el7',
            arch    => 'x86_64',
        },
        patch_available => 0,
        running_latest  => 0,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key        => 'Kernel_waiting_for_kernelcare_update',
            text       => 'The system kernel is at version “3.10.0-514.el7.x86_64”, but an update is available: 3.10.0-514.10.2.el7.x86_64',
            suggestion => 'You must take one of the following actions to ensure the system is up-to-date:<ul><li>Wait a few days for KernelCare to publish a kernel patch.</li><li>Update the system (run “yum -y update” on the command line), and reboot the system (../scripts/dialog?dialog=reboot).</li></ul>',
            type       => $Cpanel::Security::Advisor::ADVISE_INFO,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Update available & boot and running version mismatch' );

    # Begin KC patches

    %status = (
        has_kernelcare    => 1,
        unpatched_version => '3.10.0-514.el7.x86_64',
        running_version   => '3.10.0-514.2.2.el7.x86_64',
        boot_version      => '3.10.0-514.6.2.el7.x86_64',
        reboot_required   => 0,
        update_available  => undef,
        patch_available   => 1,
        running_latest    => 0,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key        => 'Kernel_kernelcare_update_available',
            text       => 'A KernelCare update is available.',
            suggestion => 'You must take one of the following actions to ensure the system is up-to-date:<ul><li>Patch the kernel (run “kcarectl --update” on the command line).</li><li>Update the system (run “yum -y update” on the command line), and reboot the system (../scripts/dialog?dialog=reboot).</li></ul>',
            type       => $Cpanel::Security::Advisor::ADVISE_BAD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Patch available' );

    $status{update_available} = {
        rpm     => 'kernel-3.10.0-514.10.2.el7.x86_64',
        name    => 'kernel',
        version => '3.10.0',
        release => '514.10.2.el7',
        arch    => 'x86_64',
    };

    # $expected is unchanged
    cmp_assessor( 'Kernel', [$expected], 'Patch and RPM available' );

    %status = (
        has_kernelcare    => 1,
        unpatched_version => '3.10.0-514.el7.x86_64',
        running_version   => '3.10.0-514.2.2.el7.x86_64',
        boot_version      => '3.10.0-514.el7.x86_64',
        reboot_required   => 0,
        update_available  => undef,
        patch_available   => 0,
        running_latest    => 1,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_kernelcare_is_current',
            text => 'KernelCare is installed and current running kernel version is up to date: 3.10.0-514.2.2.el7.x86_64',
            type => $Cpanel::Security::Advisor::ADVISE_GOOD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Patch applied, but RPM not available' );

    %status = (
        has_kernelcare    => 1,
        unpatched_version => '3.10.0-514.el7.x86_64',
        running_version   => '3.10.0-514.2.2.el7.x86_64',
        boot_version      => '3.10.0-514.2.2.el7.x86_64',
        reboot_required   => 0,
        update_available  => undef,
        patch_available   => 0,
        running_latest    => 1,
    );

    # $expected is unchanged
    cmp_assessor( 'Kernel', [$expected], 'Patch applied & RPM installed; no updates available' );

    %status = (
        has_kernelcare    => 1,
        unpatched_version => '3.10.0-514.el7.x86_64',
        running_version   => '3.10.0-514.2.2.el7.x86_64',
        boot_version      => '3.10.0-514.6.2.el7.x86_64',
        reboot_required   => 1,
        update_available  => undef,
        patch_available   => 0,
        running_latest    => 0,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_waiting_for_kernelcare_update_2',
            text => 'The system kernel has changed from version “3.10.0-514.el7.x86_64” to boot to version “3.10.0-514.6.2.el7.x86_64”. While you are fully protected by KernelCare, it may still be a good idea to reboot into the latest system kernel at your earliest convenience.',
            type => $Cpanel::Security::Advisor::ADVISE_INFO,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Waiting for patch, RPM update applied' );

    %status = (
        has_kernelcare    => 1,
        unpatched_version => '3.10.0-514.el7.x86_64',
        running_version   => '3.10.0-514.10.2.el7.x86_64',
        boot_version      => '3.10.0-514.el7.x86_64',
        reboot_required   => 0,
        update_available  => {
            rpm     => 'kernel-3.10.0-514.10.2.el7.x86_64',
            name    => 'kernel',
            version => '3.10.0',
            release => '514.10.2.el7',
            arch    => 'x86_64',
        },
        patch_available => 0,
        running_latest  => 1,
    );

    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key        => 'Kernel_update_available',
            text       => 'The system kernel will now boot version “3.10.0-514.10.2.el7.x86_64” instead of “3.10.0-514.el7.x86_64”. Although KernelCare still fully protects your server, we recommend that you reboot to the latest kernel version.',
            suggestion => 'Install the latest “kernel” RPM package to immediately boot into the latest kernel.',
            type       => $Cpanel::Security::Advisor::ADVISE_INFO,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Patch applied, but RPM not installed' );

    $status{update_excluded} = 1;
    $expected = {
        module   => 'Cpanel::Security::Advisor::Assessors::Kernel',
        function => ignore(),
        advice   => {
            key  => 'Kernel_kernelcare_is_current',
            text => 'KernelCare is installed and current running kernel version is up to date: 3.10.0-514.10.2.el7.x86_64',
            type => $Cpanel::Security::Advisor::ADVISE_GOOD,
        },
    };
    cmp_assessor( 'Kernel', [$expected], 'Patched applied, but RPM update excluded' );
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

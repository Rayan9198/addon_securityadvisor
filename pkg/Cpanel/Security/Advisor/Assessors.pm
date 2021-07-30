package Cpanel::Security::Advisor::Assessors;

# Copyright (c) 2021, cPanel, L.L.C.
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

our $VERISON = 1.1;

use Cpanel::SafeRun::Full    ();
use Cpanel::Version::Compare ();
use Cpanel::Exception        ();

sub new {
    my ( $class, $security_advisor_obj ) = @_;

    my $self = bless {
        'security_advisor_obj' => $security_advisor_obj,
        '_version'             => $VERISON
    }, $class;

    return $self;
}

sub base_path {
    my ( $self, $path ) = @_;

    if ( $ENV{'REQUEST_URI'} =~ m{cgi/securityadvisor} ) {
        return '../../' . $path;
    }
    elsif ( $ENV{'REQUEST_URI'} =~ m{cgi/addons/securityadvisor} ) {
        return '../../../' . $path;
    }

    return '../' . $path;
}

sub add_advice {
    my ( $self, %opts ) = @_;

    return $self->{'security_advisor_obj'}->add_advice( {%opts} );
}

sub add_good_advice {
    my ( $self, %opts ) = @_;

    return $self->add_advice( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_GOOD );
}

sub add_info_advice {
    my ( $self, %opts ) = @_;

    return $self->add_advice( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_INFO );
}

sub add_warn_advice {
    my ( $self, %opts ) = @_;

    return $self->add_advice( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_WARN );
}

sub add_bad_advice {
    my ( $self, %opts ) = @_;

    return $self->add_advice( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_BAD );
}

sub get_available_rpms {
    my ($self) = @_;

    my $cache = ( $self->{'security_advisor_obj'}->{'_cache'} //= {} );

    return $cache->{'available_rpms'} if $cache->{'available_rpms'};

    require Cpanel::FindBin;
    my $output = Cpanel::SafeRun::Full::run(
        'program' => Cpanel::FindBin::findbin('yum'),
        'args'    => [qw/-d 0 list all/],
        'timeout' => 90,
    );

    if ( $output->{'status'} ) {
        $cache->{'available_rpms'} = {
            map { m{\A(\S+)\.[^.\s]+\s+(\S+)} ? ( $1 => $2 ) : () }
              split( m/\n/, $output->{'stdout'} )
        };
    }

    $cache->{'timed_out'} = 1 if $output->{'timeout'};
    $cache->{'died'}      = 1 if $output->{'exit_value'} || $output->{'died_from_signal'};

    return $cache->{'available_rpms'};
}

sub get_installed_rpms {
    my ($self) = @_;

    my $cache = ( $self->{'security_advisor_obj'}->{'_cache'} //= {} );

    return $cache->{'installed_rpms'} if $cache->{'installed_rpms'};

    require Cpanel::FindBin;
    my $output = Cpanel::SafeRun::Full::run(
        'program' => Cpanel::FindBin::findbin('rpm'),
        'args'    => [ '-qa', '--queryformat', '%{NAME} %{VERSION}-%{RELEASE}\n' ],
        'timeout' => 30,
    );

    if ( $output->{'status'} ) {
        my %installed;
        for my $line ( split( "\n", $output->{'stdout'} ) ) {
            chomp $line;
            my ( $rpm, $version ) = split( qr/\s+/, $line, 2 );
            if ( $installed{$rpm} ) {
                my ( $this_version,      $this_release )      = split( m/-/, $version,         2 );
                my ( $installed_version, $installed_release ) = split( m/-/, $installed{$rpm}, 2 );

                next if ( Cpanel::Version::Compare::compare( $installed_version, '>', $this_version ) || ( $this_version eq $installed_version && Cpanel::Version::Compare::compare( $installed_release, '>', $this_release ) ) );
            }
            $installed{$rpm} = $version;
        }
        $cache->{'installed_rpms'} = \%installed;
    }

    $cache->{'timed_out'} = 1 if $output->{'timeout'};
    $cache->{'died'}      = 1 if $output->{'exit_value'} || $output->{'died_from_signal'};

    return $cache->{'installed_rpms'};
}

sub get_running_kernel_type {
    my ($kallsyms) = Cpanel::LoadFile::loadfile('/proc/kallsyms');

    my $redhat_release = Cpanel::LoadFile::loadfile('/etc/redhat-release');
    my $kernel_type =
        ( ( $kallsyms =~ /\[(kmod)?lve\]/ ) && ( $redhat_release =~ /CloudLinux/ ) ) ? 'cloudlinux'
      : ( $kallsyms =~ /grsec/ )                                                     ? 'grsec'
      : ( -e '/etc/redhat-release' )                                                 ? 'other'
      :                                                                                '';
    return $kernel_type;
}

sub _lh {
    my ($self) = @_;
    return $self->{'security_advisor_obj'}{'locale'};
}

sub get_cagefsctl_bin {
    my ($self) = @_;

    my @bins = (
        '/usr/bin/cagefsctl',
        '/usr/sbin/cagefsctl',
    );

    foreach my $bin (@bins) {
        return $bin if ( -x $bin );
    }

    return;
}

sub cagefs_is_enabled {
    my ($self) = @_;

    my $cagefsctl = $self->get_cagefsctl_bin();
    return 0 unless $cagefsctl;

    require Cpanel::SafeRun::Object;
    my $run = Cpanel::SafeRun::Object->new(
        program => $cagefsctl,
        args    => ["--cagefs-status"]
    );

    return ( $run->stdout() =~ /enabled/i ) ? 1 : 0;
}

1;

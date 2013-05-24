package Cpanel::Security::Advisor::Assessors::SSH;

# Copyright (c) 2013, cPanel, Inc.                                                                                                                                                                      
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
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use Whostmgr::Services::SSH::Config ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_ssh_settings;
}

sub _check_for_ssh_settings {
    my ($self) = @_;

    my $sshd_config = Whostmgr::Services::SSH::Config::get_config();

    if ( $sshd_config->{'PasswordAuthentication'} =~ m/yes/i || $sshd_config->{'ChallengeResponseAuthentication'} =~ m/yes/i ) {
        $self->add_bad_advice(
            'text'       => ['SSH password authentication is enabled.'],
            'suggestion' => [
                'Disable SSH password authentication in the “[output,url,_1,SSH Password Authorization Tweak,_2,_3]” area',
                '../scripts2/tweaksshauth',
                'target',
                '_blank'
            ],
        );
    }
    else {
        $self->add_good_advice(
            'text' => ['SSH password authentication is disabled.'],
        );

    }

    if ( $sshd_config->{'PermitRootLogin'} =~ m/yes/i || !$sshd_config->{'PermitRootLogin'} ) {
        $self->add_bad_advice(
            'text'       => ['SSH direct root logins are permitted.'],
            'suggestion' => [
                'Manually edit /etc/ssh/sshd_config and change PermitRootLogin to “no”, then restart SSH in the “[output,url,_1,Restart SSH,_2,_3]” area',
                '../scripts/ressshd',
                'target',
                '_blank'
            ],
        );
    }
    else {
        $self->add_good_advice(
            'text' => ['SSH direct root logins are disabled.'],
        );

    }
}

1;

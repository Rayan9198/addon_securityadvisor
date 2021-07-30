#!/usr/local/cpanel/3rdparty/bin/perl

# Copyright 2018, cPanel, L.L.C.
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

use Cpanel::Version ();
use Test::Assessor  ();
use Test::Deep;
use Test::More;
use Test::NoWarnings ();
use Test::MockModule;
use HTTP::Response;

use Cpanel::Security::Advisor::Assessors::Imunify360 ();

local $ENV{"REQUEST_URI"} = "";

plan skip_all => 'Requires cPanel & WHM v80 or later' if Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.79' );

Test::NoWarnings->import();    # defer import until this line for skip_all compatibility

my $mocked_version_module = Test::MockModule->new('Cpanel::Version');
my $imunify               = Test::MockModule->new('Whostmgr::Imunify360');
my $mocked_HTTP           = Test::MockModule->new('Cpanel::HTTP::Client');
$mocked_HTTP->redefine(
    get => sub {
        my @args = @_;
        die explain [ 'Unmocked HTTP request:', \@args ];
    }
);
my $mocked_cpstore = Test::MockModule->new('Cpanel::cPStore');

$mocked_cpstore->redefine(
    get => sub {
        [
            { item_id => '373', short_name => 'Imunify360' },    # incomplete but sufficient for the tests
        ]
    },
);

my $response_imunify_disabled = Cpanel::HTTP::Client::Response->new(
    {
        success => 1,
        status  => 200,
        content => '
            {
                "disabled": 1,
                "url": "",
                "email": ""
            }',
    }
);
$response_imunify_disabled->header( 'Content-Type', 'application/json' );

my $response_imunify_enabled = Cpanel::HTTP::Client::Response->new(
    {
        success => 1,
        status  => 200,
        content => '
            {
                "disabled": 0,
                "url": "",
                "email": ""
            }',
    }
);
$response_imunify_enabled->header( 'Content-Type', 'application/json' );

plan tests => 6 + 1;

subtest 'When Imunify360 is disabled' => sub {
    plan tests => 1;

    $mocked_version_module->redefine( getversionnumber => sub { '11.80' } );
    $mocked_HTTP->redefine( get => $response_imunify_disabled );
    my $advice = get_advice();

    is_deeply( $advice, [], "Should not return the Imunify360 advice" ) or diag explain $advice;
};

subtest 'When Imunify360 is enabled' => sub {
    plan tests => 1;

    $mocked_version_module->redefine( getversionnumber => sub { '11.80' } );
    $mocked_HTTP->redefine( get => $response_imunify_enabled );
    my $advice = get_advice();

    cmp_deeply( $advice, [ superhashof( { advice => ignore() } ) ], "Should return the Imunify360 advice" )
      or diag explain $advice;
};

$imunify->redefine( is_imunify360_licensed  => sub { 0 } );
$imunify->redefine( is_imunify360_installed => sub { 0 } );

subtest 'When Imunify360 is not installed or licensed' => sub {
    plan tests => 1;

    $imunify->redefine( is_imunify360_licensed  => sub { 0 } );
    $imunify->redefine( is_imunify360_installed => sub { 0 } );

    my $advice   = get_advice();
    my $expected = {
        'advice' => {
            'key'          => 'Imunify360_purchase',
            'block_notify' => ignore(),
            'suggestion'   => ignore(),
            'text'         => ignore(),
            'type'         => ignore(),
        },
    };

    cmp_deeply( $advice->[0], superhashof($expected), "It should advice buying an Imunify360 license" ) or diag explain $advice;
};

subtest 'When Imunify360 is installed' => sub {
    plan tests => 1;

    $imunify->redefine( is_imunify360_installed => sub { 1 } );

    my $advice   = get_advice();
    my $expected = {
        'advice' => superhashof(
            {
                'key' => 'Imunify360_present',
            }
        ),
    };

    cmp_deeply( $advice->[0], superhashof($expected), "It should say that the server is protected" ) or diag explain $advice;
};

subtest 'When the custom URL is present' => sub {
    plan tests => 1;
  SKIP: {
        if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.81' ) ) {
            skip 'Only on 82+', 1;
        }

        $imunify->redefine( get_custom_url          => sub { 'https://example.com' } );
        $imunify->redefine( is_imunify360_licensed  => sub { 0 } );
        $imunify->redefine( is_imunify360_installed => sub { 0 } );

        my $advice = get_advice();

        like( $advice->[0]->{advice}->{suggestion}, qr{https://example.com}, "It should change the link href" )
          or diag explain $advice;
    }
};

subtest 'When the custom URL is NOT present' => sub {
    plan tests => 1;

  SKIP: {
        if ( Cpanel::Version::compare( Cpanel::Version::getversionnumber(), '<', '11.81' ) ) {
            skip 'Only on 82+', 1;
        }
        $imunify->redefine( get_custom_url          => sub { '' } );
        $imunify->redefine( is_imunify360_licensed  => sub { 0 } );
        $imunify->redefine( is_imunify360_installed => sub { 0 } );

        my $advice = get_advice();

        like( $advice->[0]->{advice}->{suggestion}, qr{scripts12/purchase_imunify360_init}, "It should link to the init script" )
          or diag explain $advice;
    }
};

sub get_advice {
    my $object = Test::Assessor->new( assessor => 'Imunify360' );
    $object->generate_advice();
    my $advice = $object->get_advice();

    return $advice;
}

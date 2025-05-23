# Copyright 2017 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use strict;
use warnings;

require SyTest::Homeserver::Relapse;

package SyTest::HomeserverFactory::Relapse;
use base qw( SyTest::HomeserverFactory );

sub _init
{
   my $self = shift;
   $self->{impl} = "SyTest::Homeserver::Relapse::Direct";

   $self->{args} = {
      relapse_dir     => "../relapse",
      python          => "python",
      asyncio_reactor => 0,
      coverage        => 0,
      print_output    => 0,
      filter_output   => undef,
   };

   $self->{extra_args} = [];

   $self->SUPER::_init( @_ );
}

sub implementation_name
{
   return "relapse";
}

sub get_options
{
   my $self = shift;

   return (
      'd|relapse-directory=s' => \$self->{args}{relapse_dir},
      'python=s' => \$self->{args}{python},
      'coverage+' => \$self->{args}{coverage},
      'asyncio-reactor+' => \$self->{args}{asyncio_reactor},

      'S|server-log+' => \$self->{args}{print_output},
      'server-grep=s' => \$self->{args}{filter_output},

      'E=s' => sub { # process -Eoption=value
         my @more = split m/=/, $_[1];

         # Turn single-letter into -X but longer into --NAME
         $_ = ( length > 1 ? "--$_" : "-$_" ) for $more[0];

         push @{ $self->{extra_args} }, @more;
      },

      $self->SUPER::get_options(),
   );
}

sub print_usage
{
   print STDERR <<EOF
   -d, --relapse-directory DIR  - path to the checkout directory of relapse

       --python PATH            - path to the 'python' binary

       --coverage               - generate code coverage stats for relapse

       --asyncio-reactor        - run Relapse with the asyncio reactor enabled

   -ENAME, -ENAME=VALUE         - pass extra argument NAME or NAME=VALUE to the
                                  homeserver.
EOF
}

sub create_server
{
   my $self = shift;
   my @extra_args = @{ $self->{extra_args} };

   my %params = (
      @_,
      %{ $self->{args}},
      extra_args => \@extra_args,
   );
   return $self->{impl}->new( %params );
}


package SyTest::HomeserverFactory::Relapse::ViaHaproxy;
use base qw( SyTest::HomeserverFactory::Relapse );

sub _init
{
   my $self = shift;
   $self->SUPER::_init( @_ );
   $self->{impl} = "SyTest::Homeserver::Relapse::ViaHaproxy";
   $self->{args}{torture_replication} = 0;
   $self->{args}{redis_host} = "";
}

sub get_options
{
   my $self = shift;

   return (
      'workers'              => sub { $self->{args}{workers} = 1 },
      'torture-replication:50' => \$self->{args}{torture_replication},
      'redis-host=s'           => \$self->{args}{redis_host},
      $self->SUPER::get_options(),
   );
}

sub print_usage
{
   my $self = shift;

   $self->SUPER::print_usage();

   print STDERR <<EOF;

       --workers    - run with workers

       --torture-replication[=LEVEL] - enable torturing of the replication protocol

       --redis-host HOST 	- if set then use redis for replication
EOF
}

1;

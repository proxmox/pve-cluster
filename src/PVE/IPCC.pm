package PVE::IPCC;

use 5.010001;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use PVE::IPCC ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '1.0';

require XSLoader;
XSLoader::load('PVE::IPCC', $VERSION);

# Preloaded methods go here.

1;
__END__

=head1 NAME

PVE::IPCC - Perl extension to access the PVE IPC Server

=head1 SYNOPSIS

  use PVE::IPCC;
  
  my $res = PVE::IPCC::ipcc_send_rec(1, "hello");
 
  my $res = PVE::IPCC::sendfd($socketfd, $fd, $opt_data);

=head1 DESCRIPTION

Send/receive RAW data packets from the PVE IPC Server.

Pass file descriptor over unix domain sockets (used to pass
file destriptors to qemu fdset). This is use in PVE::QMPClient.

=head2 EXPORT

None by default.

=head1 AUTHOR

Dietmar Maurer, E<lt>dietmar@proxmox.com<gt>

=cut

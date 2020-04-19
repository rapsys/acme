# This file is part of Acmepl
#
# Acmepl is is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright (C) 2016 - 2017 Raphaël Gertz <acme@rapsys.eu>

# Acme package
package Acme;

# Best practice
use strict;
use warnings;

# Add acl support to file tests
use filetest qw(access);

# Symbol export
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(ACCOUNT CONFIG MAIL PENDING TERM THUMBPRINT VERSION);

# Load dependancies
use Carp qw(carp confess);
use Date::Parse qw(str2time);
use DateTime;
use Digest::SHA qw(sha256_base64);
use Email::Valid;
use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Slurp qw(read_file write_file);
use File::Spec qw(splitpath);
use File::stat qw(stat);
use File::Temp; # qw( :seekable );
use IPC::System::Simple qw(capturex);
use JSON qw(from_json to_json);
use LWP;
use MIME::Base64 qw(encode_base64url encode_base64);
use Net::DNS qw();
use Net::Domain::TLD qw(tld_exists);
use POSIX qw(EXIT_FAILURE);
use Tie::IxHash;

# Load debug
#use Data::Dumper;

# Documentation links
#XXX: see https://letsencrypt.github.io/acme-spec/ (probably based on https://ietf-wg-acme.github.io/acme/)
#XXX: see jwk rfc http://www.rfc-editor.org/rfc/rfc7517.txt
#XXX: see javascript implementation https://github.com/diafygi/gethttpsforfree/blob/gh-pages/js/index.js

# Set constants
use constant {
	# Config infos
	ACCOUNT => '/etc/acme/account.pem',
	CONFIG => '/etc/acme/config',
	PENDING => '/tmp/acme',
	THUMBPRINT => '/etc/acme/thumbprint',
	TERM => 'https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf',
	MAIL => 'webmaster',

	# Certificate info
	CSR_SUFFIX => '.der',

	# Redhat infos
	RH_CERTS => '/etc/pki/tls/certs',
	RH_PRIVATE => '/etc/pki/tls/private',
	RH_SUFFIX => '.pem',

	# Debian infos
	DEB_CERTS => '/etc/ssl/certs',
	DEB_PRIVATE => '/etc/ssl/private',
	DEB_CERTS_SUFFIX => '.crt',
	DEB_PRIVATE_SUFFIX => '.key',

	# Dns infos
	DNS_PREFIX => '_acme-challenge.',
	DNS_SUFFIX => '.',

	# Key infos
	KEY_TYPE => 'rsa',
	KEY_SIZE => 4096,

	# Acme infos
	#ACME_CERT => 'https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem',
	ACME_DIR => 'https://acme-staging-v02.api.letsencrypt.org/directory',
	ACME_PROD_DIR => 'https://acme-v02.api.letsencrypt.org/directory',

	# Version
	VERSION => '2.0.0',

	# Timeout
	TIMEOUT => 300
};

# User agent object
our $ua;

# Strerr backup
our $_stderr;

# JSON Web Key (JWK)
#XXX: tie to Tie::IxHash to keep a stable ordering of hash keys
#our %jwk = (
#	pubkey => undef,
#	jwk => {
#		alg => 'RS256',
#		jwk => {
#			# Exponent
#			e => undef,
#			# Key type
#			kty => uc(KEY_TYPE),
#			# Modulus
#			n => undef
#		}
#	},
#	thumbprint => undef
#);
tie(our %jwk, 'Tie::IxHash', pubkey => undef, jwk => undef, thumbprint => undef);
tie(%{$jwk{jwk}}, 'Tie::IxHash', alg => 'RS256', jwk => undef);
#XXX: strict ordering only really needed here for thumbprint sha256 digest
tie(%{$jwk{jwk}{jwk}}, 'Tie::IxHash', e => undef, kty => uc(KEY_TYPE), n => undef);

# Constructor
sub new {
	# Extract params
	my ($class, $verbose, $domain, $config) = @_;

	# Create self hash
	my $self = {};

	# Link self to package
	bless($self, $class);

	# Save verbose
	$self->{verbose} = $verbose;

	# Save domain
	$self->{domain} = $domain;

	# Save config
	$self->{config} = $config;

	# Save domains
	my @domains = ($domain->{domain}, @{$domain->{domains}});

	# Show error if check fail
	unless (defined $self->{domain}{mail}) {
		confess('Missing mail');
	}

	# Transform mail in an array
	unless (ref($self->{domain}{mail}) eq 'ARRAY') {
		$self->{domain}{mail} = [ $self->{domain}{mail} ];
	}

	# Add extra check to mail validity
	#XXX: mxcheck fail if there is only a A record on the domain
	my $ev = Email::Valid->new(-fqdn => 1, -tldcheck => 1, -mxcheck => 1);

	# Loop on each mail
	map {
		# Checke address
		if (! defined $ev->address($_)) {
			map { carp 'failed check: '.$_ if ($self->{verbose}) } $ev->details();
			confess('Validate '.$_.' mail address failed');
		}
	} @{$self->{domain}{mail}};

	# Check domains
	map {
		my $tld;

		# Extract tld
		unless (($tld) = $_ =~ m/\.(\w+)$/) {
			confess('Extract '.$_.' tld failed');
		}

		# Check if tld exists
		unless(Net::Domain::TLD::tld_exists($tld)) {
			confess('Extracted '.$_.' tld '.$tld.' do not exists');
		}

		# Search a record
		my $a = Net::DNS::Resolver->new->search($_, 'A', 'IN');

		# Search aaaa record
		my $aaaa = Net::DNS::Resolver->new->search($_, 'AAAA', 'IN');

		# Trigger error for unresolvable domain
		unless (
			# Check if either has a A or AAAA record
			scalar map {
				($_->type eq 'A' or $_->type eq 'AAAA') ? 1 : ();
			}
			# Merge both answer
			(
				(defined $a and defined $a->answer) ? $a->answer : (),
				(defined $aaaa and defined $aaaa->answer) ? $aaaa->answer : ()
			)
		) {
			confess('Resolve '.$_.' to an A or AAAA record failed');
		}
	} @domains;

	# Return class reference
	return $self;
}

# Prepare environement
sub prepare {
	my ($self) = @_;

	# Extract cert directory and filename
	my ($certFile, $certDir) = File::Spec->splitpath($self->{domain}{cert});

	# Extract key directory and filename
	my ($keyFile, $keyDir) = File::Spec->splitpath($self->{domain}{key});

	# Extract account directory and filename
	my ($accountFile, $accountDir) = File::Spec->splitpath($self->{domain}{account});

	# Create all paths
	{
		make_path($certDir, $keyDir, $accountDir, $self->{config}{pending}, {error => \my $err});
		if (@$err) {
			map {
				my ($file, $msg) = %{$_};
				carp 'Mkdir '.($file ? $file.' ' : '').'failed: '.$msg if ($self->{verbose});
			} @$err;
			confess('Make path failed');
		}
	}

	# Create user agent
	$ua = LWP::UserAgent->new;
	$ua->agent(__PACKAGE__.'/'.VERSION);

	# Check that certificate is writable
	unless (-w $certDir || -w $self->{domain}{cert}) {
		confess('Directory '.$certDir.' or file '.$self->{domain}{cert}.' must be writable: '.$!);
	}

	# Check that key is readable or parent directory is writable
	unless (-r $self->{domain}{key} || -w $keyDir) {
		confess('File '.$self->{domain}{key}.' must be readable or directory '.$keyDir.' must be writable: '.$!);
	}

	# Check that account key is readable or parent directory is writable
	unless (-r $self->{domain}{account} || -w $accountDir) {
		confess('File '.$self->{domain}{account}.' must be readable or directory '.$accountDir.' must be writable: '.$!);
	}

	# Backup old certificate if possible
	if (-w $certDir && -f $self->{domain}{cert}) {
		my ($dt, $suffix) = undef;

		# Extract datetime suffix
		$suffix = ($dt = DateTime->from_epoch(epoch => stat($self->{domain}{cert})->mtime))->ymd('').$dt->hms('');

		# Rename old certificate
		unless(copy($self->{domain}{cert}, $self->{domain}{cert}.'.'.$suffix)) {
			carp('Copy '.$self->{domain}{cert}.' to '.$self->{domain}{cert}.'.'.$suffix.' failed: '.$!);
		}
	}
}

# Drop stderr
sub _dropStdErr {
	# Save stderr
	open($_stderr, '>&STDERR') or die $!;
	# Close it
	close(STDERR) or die $!;
	# Send to /dev/null
	open(STDERR, '>', '/dev/null') or die $!;
}

# Restore stderr
sub _restoreStdErr {
	# Close stderr
	close(STDERR);
	# Open it back
	open(STDERR, '>&', $_stderr) or die $!;
}

# Generate required keys
sub genKeys {
	my ($self) = @_;

	# Generate account and server key if required
	map {
		# Check key existence
		if (! -f $_) {
			# Drop stderr
			_dropStdErr();
			# Generate key
			#XXX: we drop stderr here because openssl can't be quiet on this command
			capturex('openssl', ('genrsa', '-out', $_, KEY_SIZE));
			# Restore stderr
			_restoreStdErr();
		}
	} ($self->{domain}{account}, $self->{domain}{key});

	# Extract modulus and publicExponent jwk
	#XXX: tie to Tie::IxHash to keep a stable ordering of hash keys
	tie(%{$self->{account}}, 'Tie::IxHash', %jwk);
	map {
		if (/^Modulus=([0-9A-F]+)$/) {
			# Extract to binary from hex and convert to base64 url
			$self->{account}{jwk}{jwk}{n} = encode_base64url(pack("H*", $1) =~ s/^\0+//r);
		} elsif (/^publicExponent:\s([0-9]+)\s\(0x[0-1]+\)$/) {
			# Extract to binary from int, trim leading zeros and convert to base64 url
			chomp ($self->{account}{jwk}{jwk}{e} = encode_base64url(pack("N", $1) =~ s/^\0+//r));
		}
	} capturex('openssl', ('rsa', '-text', '-in', $self->{domain}{account}, '-noout', '-modulus'));

	# Drop stderr
	_dropStdErr();
	# Extract account public key
	$self->{account}{pubkey} = join('', map { chomp; $_; } capturex('openssl', ('rsa', '-in', $self->{domain}{account}, '-pubout')));
	# Restore stderr
	_restoreStdErr();

	# Store thumbprint
	#XXX: convert base64 to base64 url
	$self->{account}{thumbprint} = (sha256_base64(to_json($self->{account}{jwk}{jwk})) =~ s/=+\z//r) =~ tr[+/][-_]r;
}

# Directory call
sub directory {
	my ($self) = @_;

	# Set time
	my $time = time;

	# Set directory
	my $dir = $self->{domain}{prod} ? ACME_PROD_DIR : ACME_DIR;

	# Create a request
	my $req = HTTP::Request->new(GET => $dir.'?'.$time);

	# Get request
	my $res = $ua->request($req);

	# Handle error
	unless ($res->is_success) {
		confess('GET '.$dir.'?'.$time.' failed: '.$res->status_line);
	}

	# Init content
	my %content;

	# Extract content
	unless (%content = %{from_json($res->content)}) {
		confess('GET '.$dir.'?'.$time.' from_json failed: '.$res->status_line);
	}

	# Merge uris in self content
	$self->{req}{dir} = $dir;
	$self->{req}{keyChange} = $content{keyChange};
	$self->{req}{newNonce} = $content{newNonce};
	$self->{req}{newAccount} = $content{newAccount};
	$self->{req}{revokeCert} = $content{revokeCert};
	$self->{req}{newOrder} = $content{newOrder};

	# Check term
	unless ($self->{config}{term} eq $content{meta}{termsOfService}) {
		confess('GET '.$dir.'?'.$time.' term: '.$content{meta}{termsOfService}.' differ from config: '.$self->{config}{term});
	}
}

# Nonce call
sub nonce {
	my ($self) = @_;

	# Set time
	my $time = time;

	# Create a request
	my $req = HTTP::Request->new(HEAD => $self->{req}{newNonce}.'?'.$time);

	# Get request
	my $res = $ua->request($req);

	# Handle error
	unless ($res->is_success) {
		confess('HEAD '.$self->{req}{newNonce}.'?'.$time.' failed: '.$res->status_line);
	}

	# Save nonce
	$self->{req}{nonce} = $res->headers->{'replay-nonce'};
}

# Post request
sub _post {
	my ($self, $uri, $payload) = @_;

	# Init protected
	#XXX: tie to Tie::IxHash to keep a stable ordering of hash keys
	#XXX: strict ordering only really needed here for thumbprint sha256 digest
	tie(my %protected, 'Tie::IxHash', alg => $self->{account}{jwk}{alg}, jwk => $self->{account}{jwk}{jwk}, nonce => $self->{req}{nonce}, url => $uri);

	# We have a kid
	if (defined($self->{req}{kid})) {
		# Replace jwk entry with it
		#XXX: when kid is available all request with jwk are rejected by the api
		%protected = (alg => $self->{account}{jwk}{alg}, kid => $self->{req}{kid}, nonce => $self->{req}{nonce}, url => $uri);
	}

	# Encode protected
	my $protected = encode_base64url(to_json(\%protected));

	# Encode payload
	$payload = encode_base64url(to_json($payload)) unless ($payload eq '');

	# Sign temp file
	my $stf = File::Temp->new();

	# Append protect.payload to stf
	print $stf $protected.'.'.$payload;

	# Close stf
	close($stf);

	# Generate digest of stf
	my $signature = encode_base64url(join('', capturex('openssl', ('dgst', '-sha256', '-binary', '-sign', $self->{domain}{account}, $stf->filename))) =~ s/^\0+//r);

	# Create a request
	my $req = HTTP::Request->new(POST => $uri);

	# Set request header
	$req->header('Content-Type' => 'application/jose+json');

	# Set new-reg request content
	$req->content(to_json({
		protected => $protected,
		payload => $payload,
		signature => $signature
	}));

	# Post request
	my $res = $ua->request($req);

	# Save nonce
	if (defined $res->headers->{'replay-nonce'}) {
		$self->{req}{nonce} = $res->headers->{'replay-nonce'};
	}

	# Return res object
	return $res;
}

# Resolve dns and check content
#XXX: see https://community.centminmod.com/threads/looks-like-letsencrypt-dns-01-is-ready.5845/#12 for example
sub _dnsCheck {
	my ($self, $domain, $token) = @_;

	# Generate signature from content
	my $signature = ((sha256_base64($token.'.'.$self->{account}{thumbprint})) =~ s/=+\z//r) =~ tr[+/][-_]r;

	# Search txt record
	my $txt = Net::DNS::Resolver->new->search(DNS_PREFIX.$domain.DNS_SUFFIX, 'TXT', 'IN');

	# Check that we have a txt record
	unless (defined $txt and defined $txt->answer and scalar map { $_->type eq 'TXT' ? 1 : (); } $txt->answer) {
		carp 'Resolve '.DNS_PREFIX.$domain.DNS_SUFFIX.' to a TXT record failed' if ($self->{verbose});
		return;
	}

	# Check that txt record data match signature
	unless (scalar map { ($_->type eq 'TXT' and $_->txtdata eq $signature) ? 1 : (); } $txt->answer) {
		# Check verbose
		if ($self->{verbose}) {
			# Loop on each answer
			map {
				# Check if we have a TXT record with different value
				if ($_->type eq 'TXT' and $_->txtdata ne $signature) {
					carp 'Resolved '.DNS_PREFIX.$domain.DNS_SUFFIX.' with "'.$_->txtdata.'" instead of "'.$signature.'"';
				}
			} $txt->answer;
		}
		return;
	}

	# Return success
	return 1;
}

# Get uri and check content
sub _httpCheck {
	my ($self, $domain, $token) = @_;

	# Create a request
	my $req = HTTP::Request->new(GET => 'http://'.$domain.'/.well-known/acme-challenge/'.$token);

	# Check if thumbprint is writeable
	if (-w $self->{config}{thumbprint}) {
		# Try to write thumbprint
		write_file($self->{config}{thumbprint}, $self->{account}{thumbprint});
	}

	# Get request
	my $res = $ua->request($req);

	# Handle error
	unless ($res->is_success) {
		carp 'Fetch http://'.$domain.'/.well-known/acme-challenge/'.$token.' failed: '.$res->status_line if ($self->{verbose});
		return;
	}

	# Handle invalid content
	unless($res->content =~ /^$token.$self->{account}{thumbprint}\s*$/) {
		carp 'Fetched http://'.$domain.'/.well-known/acme-challenge/'.$token.' with "'.$res->content.'" instead of "'.$token.'.'.$self->{account}{thumbprint}.'"' if ($self->{verbose});
		return;
	}

	# Return success
	return 1;
}

# Register account
#XXX: see doc at https://ietf-wg-acme.github.io/acme/#rfc.section.6.3
sub account {
	my ($self) = @_;

	# Init pending directory
	$self->{req}{pending} = $self->{config}{pending}.'/'.encode_base64url($self->{req}{dir}).'/'.encode_base64url(join(',', @{$self->{domain}{mail}}));

	# Create pending directory
	{
		make_path($self->{req}{pending}, {error => \my $err});
		if (@$err) {
			map {
				my ($file, $msg) = %{$_};
				carp 'Mkdir '.($file ? $file.' ' : '').'failed: '.$msg if ($self->{verbose});
			} @$err;
			confess('Make path failed');
		}
	}

	# Init file
	#XXX: we use this file to store the fetched account
	my $file = $self->{req}{pending}.'/'.(((sha256_base64(join(',', @{$self->{domain}{mail}}))) =~ s/=+\z//r) =~ tr[+/][-_]r);

	# Init content
	my $content = undef;

	# Load account content or post a new one
	if (
		#XXX: use eval to workaround a fatal in from_json
		! defined eval {
			# Check that file exists
			-f $file &&
			# Read it
			($content = read_file($file)) &&
			# Decode it
			($content = from_json($content))
		}
	) {
		# Init tied payload
		#XXX: tie to Tie::IxHash to keep a stable ordering of hash keys
		tie(my %payload, 'Tie::IxHash', termsOfServiceAgreed => JSON::true, contact => []);

		# Loop on mails
		map {
			# Append mail to payload
			$payload{contact}[scalar @{$payload{contact}}] = 'mailto:'.$_;
		} @{$self->{domain}{mail}};

		# Post newAccount request
		# TODO: change contact field in config to contain directly the array [mailto:example@example.com,...] ???
		#XXX: contact array may contain a tel:+33612345678 for example (supported ???)
		my $res = $self->_post($self->{req}{'newAccount'}, \%payload);

		# Handle error
		unless ($res->is_success) {
			confess('POST '.$self->{req}{'newAccount'}.' failed: '.$res->status_line)
		}

		# Store kid from header location
		$content = {
			'kid' => $res->headers->{location},
		};

		# Write to file
		write_file($file, to_json($content));
	}

	# Set kid from content
	$self->{req}{kid} = $content->{kid};

}

# Authorize domains
sub order {
	my ($self) = @_;

	# Init file
	#XXX: we use this file to store the requested domains on our side
	#XXX: see bug https://github.com/letsencrypt/boulder/issues/3335 and https://community.letsencrypt.org/t/acmev2-orders-list/51662
	my $file = $self->{req}{pending}.'/'.(((sha256_base64(join(',', ($self->{domain}{domain}, @{$self->{domain}{domains}})))) =~ s/=+\z//r) =~ tr[+/][-_]r);

	# Init content
	my $content = undef;

	# Load account content or post a new one
	if (
		#XXX: use eval to workaround a fatal in from_json
		! defined eval {
			# Check that file exists
			-f $file &&
			# Read it
			($content = read_file($file)) &&
			# Decode it
			($content = from_json($content))
		# Check expiration
		} || (str2time($content->{expires}) <= time()+3600)
	) {
		# Init tied payload
		#XXX: tie to Tie::IxHash to keep a stable ordering of hash keys
		#XXX: https://www.perlmonks.org/?node_id=1215976
		#XXX: optional notBefore, notAfter, see https://ietf-wg-acme.github.io/acme/draft-ietf-acme-acme.html#applying-for-certificate-issuance
		tie(my %payload, 'Tie::IxHash', identifiers => []);

		# Loop on domains
		map {
			# Tie in a stable hash and append to identifiers array
			#XXX: tie to Tie::IxHash to keep a stable ordering of hash keys
			tie(%{$payload{identifiers}[scalar @{$payload{identifiers}}]}, 'Tie::IxHash', type => 'dns', value => $_);
		} ($self->{domain}{domain}, @{$self->{domain}{domains}});

		# Post new order request
		my $res = $self->_post($self->{req}{'newOrder'}, \%payload);

		# Handle error
		unless ($res->is_success) {
			confess('POST '.$self->{req}{'newOrder'}.' failed: '.$res->status_line);
		}

		# Handle error
		unless ($res->content) {
			confess('POST '.$self->{req}{'newOrder'}.' empty content: '.$res->status_line);
		}

		# Handle error
		unless ($res->headers->{location}) {
			confess('POST '.$self->{req}{'newOrder'}.' missing location: '.$res->status_line);
		}

		# Extract content
		$content = from_json($res->content);

		# Write to file
		write_file($file, to_json($content));
	}

	# Save the authorizations
	$self->{req}{authorizations} = [ keys %{{ map { $_ => undef } @{$content->{authorizations}} }} ];

	# Save the finalize uri
	$self->{req}{finalize} = $content->{finalize};

	# Create challenges hash
	%{$self->{req}{challenges}} = ();

	# Extract authorizations
	map {
		# Init uri
		my $uri = $_;

		# Init content
		my $content = undef;

		# Init file
		#XXX: tmpdir.'/'.<orderuri>.'/'.<authuri>
		my $file = $self->{req}{pending}.'/'.encode_base64url($uri);

		# Load auth request content or post a new one
		#TODO: add more check on cache file ???
		if (
			#XXX: use eval to workaround a fatal in from_json
			! defined eval {
				# Check that file exists
				-f $file &&
				# Read it
				($content = read_file($file)) &&
				# Decode it
				($content = from_json($content))
			# Check expiration
			} || (str2time($content->{expires}) <= time()+3600)
		) {
			# Post new-authz request
			my $res = $self->_post($uri, '');

			# Handle error
			unless ($res->is_success) {
				confess('POST '.$uri.' failed: '.$res->status_line);
			}

			# Decode content
			$content = from_json($res->content);

			# Check identifier
			unless (
				defined $content->{identifier} and
				defined $content->{identifier}{type} and
				defined $content->{identifier}{value}
			) {
				confess('POST '.$uri.' missing identifier: '.$res->status_line);
			} else {
				unless (
					$content->{identifier}{type} eq 'dns' and
					$content->{identifier}{value}
				) {
					confess('POST '.$uri.' invalid identifier: '.$res->status_line);
				}
			}

			# Check status
			unless ($content->{status} eq 'valid' or $content->{status} eq 'pending') {
				confess('POST '.$uri.' for '.$content->{identifier}{value}.' failed: '.$res->status_line);
			}

			# Write to file
			write_file($file, to_json($content));
		}

		# Add challenge
		%{$self->{req}{challenges}{$content->{identifier}{value}}} = (
			status => $content->{status},
			expires => $content->{expires},
			challenges => {},
			polls => {}
		);

		# Extract challenges
		map {
			# Save if valid
			if ($_->{status} eq 'valid') {
				$self->{req}{challenges}{$content->{identifier}{value}}{status} = $_->{status};
			# Check is still polling
			} elsif ($content->{status} eq 'pending') {
				# Add to challenges list for later use
				$self->{req}{challenges}{$content->{identifier}{value}}{challenges}{$_->{type}} = {
					status => $_->{status},
					token => $_->{token},
					url => $_->{url}
				};
			}
		} @{$content->{challenges}};

		# Set identifier
		my $identifier = $content->{identifier}{value};

		# Save pending data
		if ($self->{req}{challenges}{$identifier}{status} eq 'pending') {
			# Check challenges
			map {
				# One test already validated this auth request
				unless($self->{req}{challenges}{$identifier}{status} eq 'valid') {
					# One challenge validated
					if ($self->{req}{challenges}{$identifier}{challenges}{$_}{status} eq 'valid') {
						$self->{req}{challenges}{$identifier}{status} = $self->{req}{challenges}{$identifier}{challenges}{$_}{status};
					# This challenge is to be validated
					} elsif ($self->{req}{challenges}{$identifier}{challenges}{$_}{status} eq 'pending') {
						#TODO: implement tls-alpn-01 challenge someday if possible
						if (
							($_ eq 'http-01' and $self->_httpCheck($identifier, $self->{req}{challenges}{$identifier}{challenges}{$_}{token})) or
							($_ eq 'dns-01' and $self->_dnsCheck($identifier, $self->{req}{challenges}{$identifier}{challenges}{$_}{token}))
						) {
							# Init file
							#XXX: tmpdir.'/'.<orderuri>.'/'.<authuri>
							my $file = $self->{req}{pending}.'/'.encode_base64url($self->{req}{challenges}{$identifier}{challenges}{$_}{url});

							# Reset content
							$content = undef;

							# Load auth request content or post a new one
							#TODO: add more check on cache file ???
							if (
								#XXX: use eval to workaround a fatal in from_json
								! defined eval {
									# Check that file exists
									-f $file &&
									# Read it
									($content = read_file($file)) &&
									# Decode it
									($content = from_json($content))
								#TODO: Check file modification time ? There is no expires field in json answer
								}# || (str2time($content->{expires}) <= time()+3600)
							) {
								# Post challenge request
								my $res = $self->_post(
									$self->{req}{challenges}{$identifier}{challenges}{$_}{url},
									{keyAuthorization => $self->{req}{challenges}{$identifier}{challenges}{$_}{token}.'.'.$self->{account}{thumbprint}}
								);

								# Handle error
								unless ($res->is_success) {
									confess('POST '.$self->{req}{challenges}{$identifier}{challenges}{$_}{url}.' failed: '.$res->status_line);
								}

								# Extract content
								$content = from_json($res->content);

								# Write to file
								write_file($file, to_json($content));
							}

							# Save if valid
							if ($content->{status} eq 'valid') {
								$self->{req}{challenges}{$identifier}{status} = $content->{status};
							# Check is still polling
							} elsif ($content->{status} eq 'pending') {
								# Add to poll list for later use
								$self->{req}{challenges}{$identifier}{polls}{$content->{type}} = 1;
							}
						}
					}
				}
			} keys %{$self->{req}{challenges}{$identifier}{challenges}};

			# Check if check is challenge still in pending and no polls
			if ($self->{req}{challenges}{$identifier}{status} eq 'pending' && scalar keys %{$self->{req}{challenges}{$identifier}{polls}} == 0) {
				# Loop on all remaining challenges
				map {
					#TODO: implement tls-alpn-01 challenge someday if possible
					# Display help for http-01 check
					if ($_ eq 'http-01') {
						print STDERR 'Require URI http://'.$identifier.'/.well-known/acme-challenge/'.$self->{req}{challenges}{$identifier}{challenges}{$_}{token}.' with "'.$self->{req}{challenges}{$identifier}{challenges}{$_}{token}.'.'.$self->{account}{thumbprint}.'"'."\n";
					# Display help for dns-01 check
					} elsif ($_ eq 'dns-01') {
						print STDERR 'Require TXT record _acme-challenge.'.$identifier.'. with "'.(((sha256_base64($self->{req}{challenges}{$identifier}{challenges}{$_}{token}.'.'.$self->{account}{thumbprint})) =~ s/=+\z//r) =~ tr[+/][-_]r).'"'."\n";
					}
				} keys %{$self->{req}{challenges}{$identifier}{challenges}};
			}
		}
	} @{$self->{req}{authorizations}};

	# Init max run
	my $remaining = TIMEOUT;

	# Poll pending
	while (--$remaining >= 0 and scalar map { ($_->{status} eq 'pending' and scalar keys %{$_->{polls}}) ? 1 : (); } values %{$self->{req}{challenges}}) {
		# Sleep
		sleep(1);

		# Poll remaining pending
		map {
			# Init identifier
			my $identifier = $_;

			# Poll remaining polls
			map {
				# Post challenge request
				#XXX: no cache here we force update
				my $res = $self->_post(
					$self->{req}{challenges}{$identifier}{challenges}{$_}{url},
					{keyAuthorization => $self->{req}{challenges}{$identifier}{challenges}{$_}{token}.'.'.$self->{account}{thumbprint}}
				);

				# Handle error
				unless ($res->is_success) {
					confess('POST '.$self->{req}{challenges}{$identifier}{challenges}{$_}{url}.' failed: '.$res->status_line);
				}

				# Extract content
				$content = from_json($res->content);

				# Init file
				#XXX: tmpdir.'/'.<orderuri>.'/'.<authuri>
				my $file = $self->{req}{pending}.'/'.encode_base64url($self->{req}{challenges}{$identifier}{challenges}{$_}{url});

				# Write to file
				write_file($file, to_json($content));

				# Save status
				if ($content->{status} ne 'pending') {
					$self->{req}{challenges}{$identifier}{status} = $content->{status};
				}
			} keys %{$self->{req}{challenges}{$identifier}{polls}};
		} map { $self->{req}{challenges}{$_}{status} eq 'pending' ? $_ : (); } keys %{$self->{req}{challenges}};
	} 


	# Check if thumbprint is writeable
	if (-w $self->{config}{thumbprint}) {
		# Try to write thumbprint
		write_file($self->{config}{thumbprint}, '');
	}

	# Stop here with remaining challenge
	if (scalar map { $_->{status} ne 'valid' ? 1 : (); } values %{$self->{req}{challenges}}) {
		#TODO: Deactivate all activated domains ?
		#XXX: see if implemented by letsencrypt ACMEv2
		#map {
		#	# Post deactivation request
		#	my $res = $self->_post($self->{challenges}{$_}{http_uri}, {resource => 'authz', status => 'deactivated'});
		#	# Handle error
		#	unless ($res->is_success) {
		#		confess('POST '.$self->{challenges}{$_}{http_uri}.' failed: '.$res->status_line);
		#	}
		#} map { $self->{challenges}{$_}{status} eq 'valid' ? $_ : () } keys %{$self->{challenges}};

		# Stop here as a domain of csr list failed authorization
		if ($self->{verbose}) {
			my @domains = map { $self->{req}{challenges}{$_}{status} ne 'valid' ? $_ : (); } keys %{$self->{req}{challenges}};
			#my @domains = map { ! defined $self->{challenges}{$_}{status} or $self->{challenges}{$_}{status} ne 'valid' ? $_ : (); } keys %{$self->{challenges}};
			carp 'Fix challenge'.(scalar @domains > 1?'s':'').' for: '.join(', ', @domains);
		}
		exit EXIT_FAILURE;
	}
}

# Generate certificate request
sub genCsr {
	my ($self) = @_;

	# Init csr file
	#XXX: tmpdir.'/'.<orderuri>.'/'.<thumbprint>.':'.<mail>.':'.join(',', @domains).'.<prodstaging>.'.CSR_SUFFIX
	$self->{req}{csr} = $self->{req}{pending}.'/'.(((sha256_base64(join(',', ($self->{domain}{domain}, @{$self->{domain}{domains}})))) =~ s/=+\z//r) =~ tr[+/][-_]r).CSR_SUFFIX;

	# Reuse certificate request file without domain/mail change
	if (! -f $self->{req}{csr}) {
		# Openssl config template
		my $oct = File::Temp->new(UNLINK => 0);

		# Save data start position
		my $pos = tell DATA;

		# Init counter
		my $i = 0;

		# Prepare mail
		my $mail = join("\n", map { $i++.'.emailAddress'."\t\t\t".'= '.$_; } @{$self->{domain}{mail}});

		# Load template from data
		map { s/__EMAIL_ADDRESS__/$mail/; s/__COMMON_NAME__/$self->{domain}{domain}/; print $oct $_; } <DATA>;

		# Reseek data
		seek(DATA, $pos, 0);

		# Append domain names
		$i = 0;
		map { print $oct 'DNS.'.$i++.' = '.$_."\n"; } ($self->{domain}{domain}, @{$self->{domain}{domains}});

		# Generate csr
		#XXX: read certificate request with: openssl req -inform DER -in $self->{req}{csr} -text
		capturex('openssl', ('req', '-new', '-outform', 'DER', '-key', $self->{domain}{key}, '-config', $oct->filename, '-out', $self->{req}{csr}));

		# Close oct
		close($oct);
	}
}

# Issue certificate
sub issue {
	my ($self) = @_;

	# Open csr file
	open(my $fh, '<', $self->{req}{csr}) or die $!;

	# Load csr
	my $csr = encode_base64url(join('', <$fh>) =~ s/^\0+//r);

	# Close csr file
	close($fh) or die $!;

	# Init file
	#XXX: tmpdir.'/'.<orderuri>.'/'.<finalizeuri>
	my $file = $self->{req}{pending}.'/'.encode_base64url($self->{req}{finalize});

	# Init content
	my $content = undef;

	# Init res
	my $res = undef;

	# Load auth request content or post a new one
	#TODO: add more check on cache file ???
	if (
		#XXX: use eval to workaround a fatal in from_json
		! defined eval {
			# Check that file exists
			-f $file &&
			# Read it
			($content = read_file($file)) &&
			# Decode it
			($content = from_json($content))
		# Check file modification time ? There is no expires field in json answer
		} || (str2time($content->{expires}) <= time()+3600)
	) {
		# Post certificate request
		$res = $self->_post($self->{req}{finalize}, {csr => $csr});

		# Handle error
		unless ($res->is_success) {
			confess('POST '.$self->{req}{finalize}.' failed: '.$res->status_line);
		}

		# Extract content
		$content = from_json($res->content);

		# Check status
		unless (defined $content->{status} and $content->{status} eq 'valid') {
			confess('POST '.$self->{req}{finalize}.' failed: invalid status: '.(defined $content->{status}?$content->{status}:'undefined'));
		}

		# Check certificate
		unless (defined $content->{certificate} and $content->{certificate}) {
			confess('POST '.$self->{req}{finalize}.' failed: invalid certificate: '.(defined $content->{certificate}?$content->{certificate}:'undefined'));
		}

		# Write to file
		write_file($file, to_json($content));
	}

	# Set certificate
	$self->{req}{certificate} = $content->{certificate};

	# Set file
	#XXX: tmpdir.'/'.<orderuri>.'/'.<certificateuri>
	$file = $self->{req}{pending}.'/'.encode_base64url($self->{req}{certificate});

	# Reset content
	$content = undef;

	# Load auth request content or post a new one
	#TODO: add more check on cache file ???
	if (
		#XXX: use eval to workaround a fatal in from_json
		! defined eval {
			# Check that file exists
			-f $file &&
			# Read it
			($content = read_file($file))
		# Check file modification time ? There is no expires field in json answer
		#TODO: add a checck on modification time ???
		}# || (str2time($content->{expires}) <= time()+3600)
	) {
		# Post certificate request
		$res = $self->_post($self->{req}{certificate}, '');

		# Handle error
		unless ($res->is_success) {
			confess('POST '.$self->{req}{certificate}.' failed: '.$res->status_line);
		}

		# Set content
		$content = $res->content;

		# Remove multi-line jump
		$content =~ s/\n\n/\n/;

		# Remove trailing line jump
		chomp $content;

		# Write to file
		write_file($file, $content);
	}

	# Write to cert file
	write_file($self->{domain}{cert}, $content);

	# Print success
	carp 'Saved '.$self->{domain}{cert}.' pem certificate' if ($self->{verbose});
}

1;

__DATA__
#
# OpenSSL configuration file.
# This is mostly being used for generation of certificate requests.
#

[ req ]
default_bits		= 2048
default_md		= sha256
prompt			= no
distinguished_name	= req_distinguished_name
# The extentions to add to the self signed cert
x509_extensions	= v3_ca
# The extensions to add to a certificate request
req_extensions = v3_req

# This sets a mask for permitted string types. There are several options. 
# utf8only: only UTF8Strings (PKIX recommendation after 2004).
# WARNING: ancient versions of Netscape crash on BMPStrings or UTF8Strings.
string_mask = utf8only

[ req_distinguished_name ]
countryName			= US
stateOrProvinceName		= State or Province Name
localityName			= Locality Name
organizationName		= Organization Name
organizationalUnitName		= Organizational Unit Name
commonName			= __COMMON_NAME__
__EMAIL_ADDRESS__

[ v3_req ]
basicConstraints = CA:false
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = email:move
subjectAltName = @alt_names

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:true

[alt_names]

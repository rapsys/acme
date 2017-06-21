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

# Fix use of acl
use filetest qw(access);

# Symbol export
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(VERSION);

# Load dependancies
use Carp qw(carp confess);
use Date::Parse qw(str2time);
use DateTime;
use Digest::SHA qw(sha256_base64);
use Email::Valid;
use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Slurp qw(read_file write_file);
use File::stat qw(stat);
use File::Temp; # qw( :seekable );
use IPC::System::Simple qw(capturex);
use JSON qw(from_json to_json);
use LWP;
use MIME::Base64 qw(encode_base64url encode_base64);
use Net::Domain::TLD;
use POSIX qw(EXIT_FAILURE);
use Tie::IxHash;

# Debug
use Data::Dumper;

# Documentation links
#XXX: see https://letsencrypt.github.io/acme-spec/ (probably based on https://ietf-wg-acme.github.io/acme/)
#XXX: see jwk rfc http://www.rfc-editor.org/rfc/rfc7517.txt
#XXX: see javascript implementation https://github.com/diafygi/gethttpsforfree/blob/gh-pages/js/index.js

# Set constants
use constant {
	# Request certificate file name
	REQUEST_CSR => 'request.der',

	# rsa
	KEY_TYPE => 'rsa',

	# 2048|4096
	KEY_SIZE => 4096,

	# Acme infos
	ACME_CERT => 'https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem',
	ACME_DIR => 'https://acme-staging.api.letsencrypt.org/directory',
	ACME_PROD_DIR => 'https://acme-v01.api.letsencrypt.org/directory',

	# Version
	VERSION => 'v0.9',
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
	my ($class, $debug, $domain, $config) = @_;

	# Create self hash
	my $self = {};

	# Link self to package
	bless($self, $class);

	# Save debug
	$self->{debug} = $debug;

	# Save domain
	$self->{domain} = $domain;

	# Save config
	$self->{config} = $config;

	# Save domains
	@{$self->{domains}} = ($domain->{domain}, @{$domain->{domains}});

	# Add extra check to mail validity
	#XXX: mxcheck fail if there is only a A record on the domain
	my $ev = Email::Valid->new(-fqdn => 1, -tldcheck => 1, -mxcheck => 1);

	# Show error if check fail
	if (! defined $ev->address($self->{domain}{mail})) {
		map { carp 'failed check: '.$_ if ($self->{debug}) } $ev->details();
		confess 'Email::Valid->address failed';
	}

	# Save mail
	$self->{mail} = $self->{domain}{mail};

	# Create resolver
	my $res = new Net::DNS::Resolver();

	# Check domains
	map {
		my $tld;

		# Extract tld
		unless (($tld) = $_ =~ m/\.(\w+)$/) {
			confess $_.'\'s tld extraction failed';
		}

		# Check if tld exists
		unless(Net::Domain::TLD::tld_exists($tld)) {
			confess $tld.' tld from '.$_.' don\'t exists';
		}

		# Check if we get dns answer
		#XXX: only search A type because letsencrypt don't support ipv6 (AAAA) yet
		unless(my $rep = $res->search($_, 'A')) {
			confess 'search A record for '.$_.' failed';
		} else {
			unless (scalar map { $_->type eq 'A' ? 1 : (); } $rep->answer) {
				confess 'search recursively A record for '.$_.' failed';
			}
		}
	} @{$self->{domains}};

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
		make_path($certDir, $keyDir, $accountDir, $self->{config}{pending}.'/'.$self->{mail}.'.'.($self->{domain}{prod} ? 'prod' : 'staging'), {error => \my $err});
		if (@$err) {
			map {
				my ($file, $msg) = %$_;
				carp ($file eq '' ? '' : $file.': ').$msg if ($self->{debug});
			} @$err;
			confess 'make_path failed';
		}
	}

	# Create user agent
	$ua = LWP::UserAgent->new;
	$ua->agent(__PACKAGE__.'/'.VERSION);

	# Check that certificate is writable
	unless (-w $certDir || -w $self->{domain}{cert}) {
		confess('Directory '.$certDir.' or file '.$self->{domain}{cert}.' must be writable: '.$!);
	}

	# Check that key is writable
	unless (-r $self->{domain}{key} || -w $keyDir) {
		confess('File '.$self->{domain}{key}.' must be readable or directory '.$keyDir.' must be writable: '.$!);
	}

	# Check that account is writable
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
	#XXX: same here we tie to keep ordering
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

# Generate certificate request
sub genCsr {
	my ($self) = @_;

	# Openssl config template
	my $oct = File::Temp->new();

	# Save data start position
	my $pos = tell DATA;

	# Load template from data
	map { s/__EMAIL_ADDRESS__/$self->{mail}/; s/__COMMON_NAME__/$self->{domains}[0]/; print $oct $_; } <DATA>;

	# Reseek data
	seek(DATA, $pos, 0);

	# Append domain names
	my $i = 1;
	map { print $oct 'DNS.'.$i++.' = '.$_."\n"; } @{$self->{domains}};

	# Generate csr
	capturex('openssl', ('req', '-new', '-outform', 'DER', '-key', $self->{domain}{key}, '-config', $oct->filename, '-out', $self->{config}{pending}.'/'.$self->{mail}.'.'.($self->{domain}{prod} ? 'prod' : 'staging').'/'.REQUEST_CSR));

	# Close oct
	close($oct);
}

# Directory call
sub directory {
	my ($self) = @_;

	# Set time
	my $time = time;

	# Set directory
	my $dir = $self->{prod} ? ACME_PROD_DIR : ACME_DIR;

	# Create a request
	my $req = HTTP::Request->new(GET => $dir.'?'.$time);

	# Get request
	my $res = $ua->request($req);

	# Handle error
	unless ($res->is_success) {
		confess 'GET '.$dir.'?'.$time.' failed: '.$res->status_line;
	}

	# Save nonce
	$self->{nonce} = $res->headers->{'replay-nonce'};

	# Merge uris in self content
	%$self = (%$self, %{from_json($res->content)});
}

# Post request
sub _post {
	my ($self, $uri, $payload) = @_;

	# Protected field
	my $protected = encode_base64url(to_json({nonce => $self->{nonce}}));

	# Payload field
	$payload = encode_base64url(to_json($payload));

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
	
	# Set new-reg request content
	$req->content(to_json({
		header => $self->{account}{jwk},
		protected => $protected,
		payload => $payload,
		signature => $signature
	}));

	# Post request
	my $res = $ua->request($req);

	# Save nonce
	if (defined $res->headers->{'replay-nonce'}) {
		$self->{nonce} = $res->headers->{'replay-nonce'};
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

	# Fix domain
	$domain = '_acme-challenge.'.$domain.'.';

	# Create resolver
	my $res = new Net::DNS::Resolver();

	# Check if we get dns answer
	unless(my $rep = $res->search($domain, 'TXT')) {
		carp 'TXT record search for '.$domain.' failed' if ($self->{debug});
		return;
	} else {
		unless (scalar map { $_->type eq 'TXT' && $_->txtdata =~ /^$signature$/ ? 1 : (); } $rep->answer) {
			carp 'TXT record recursive search for '.$domain.' failed' if ($self->{debug});
			return;
		}
	}

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
		carp 'GET http://'.$domain.'/.well-known/acme-challenge/'.$token.' failed: '.$res->status_line if ($self->{debug});
		return;
	}

	# Handle invalid content
	unless($res->content =~ /^$token.$self->{account}{thumbprint}\s*$/) {
		carp 'GET http://'.$domain.'/.well-known/acme-challenge/'.$token.' content match failed: /^'.$token.'.'.$self->{account}{thumbprint}.'\s*$/ !~ '.$res->content if ($self->{debug});
		return;
	}

	# Return success
	return 1;
}

# Register account
#XXX: see doc at https://ietf-wg-acme.github.io/acme/#rfc.section.6.3
sub register {
	my ($self) = @_;

	# Post new-reg request
	#XXX: contact array may contain a tel:+33612345678 for example
	my $res = $self->_post($self->{'new-reg'}, {resource => 'new-reg', contact => ['mailto:'.$self->{mail}], agreement => $self->{term}});

	# Handle error
	unless ($res->is_success || $res->code eq 409) {
		confess 'POST '.$self->{'new-reg'}.' failed: '.$res->status_line;
	}

	# Update mail informations
	if ($res->code eq 409) {
		# Save registration uri
		$self->{'reg'} = $res->headers->{location};

		# Post reg request
		#XXX: contact array may contain a tel:+33612345678 for example
		$res = $self->_post($self->{'reg'}, {resource => 'reg', contact => ['mailto:'.$self->{mail}]});

		# Handle error
		unless ($res->is_success) {
			confess 'POST '.$self->{'reg'}.' failed: '.$res->status_line;
		}
	}
}

# Authorize domains
sub authorize {
	my ($self) = @_;

	# Create challenges hash
	%{$self->{challenges}} = ();

	# Pending list
	my @pending = ();

	# Create or load auth request for each domain
	map {
		# Init content
		my $content = undef;

		# Init file
		my $file = $self->{config}{pending}.'/'.$self->{mail}.'.'.($self->{domain}{prod} ? 'prod' : 'staging').'/'.$_;

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
			my $res = $self->_post($self->{'new-authz'}, {resource => 'new-authz', identifier => {type => 'dns', value => $_}, existing => 'accept'});

			# Handle error
			unless ($res->is_success) {
				confess 'POST '.$self->{'new-authz'}.' for '.$_.' failed: '.$res->status_line;
			}

			# Decode content
			$content = from_json($res->content);

			# Check domain
			unless (defined $content->{identifier}{value} && $content->{identifier}{value} eq $_) {
				confess 'domain matching '.$content->{identifier}{value}.' for '.$_.' failed: '.$res->status_line;
			}

			# Check status
			unless ($content->{status} eq 'valid' or $content->{status} eq 'pending') {
				confess 'POST '.$self->{'new-authz'}.' for '.$_.' failed: '.$res->status_line;
			}

			# Write to file
			write_file($file, to_json($content));
		}

		# Add challenge
		%{$self->{challenges}{$_}} = (
			status => $content->{status},
			expires => $content->{expires},
			polls => []
		);

		# Save pending data
		if ($content->{status} eq 'pending') {
			# Extract validation data
			foreach my $challenge (@{$content->{challenges}}) {
				# One test already validated this auth request
				if ($self->{challenges}{$_}{status} eq 'valid') {
					next;
				} elsif ($challenge->{status} eq 'valid') {
					$self->{challenges}{$_}{status} = $challenge->{status};
					next;
				} elsif ($challenge->{status} eq 'pending') {
					# Handle check
					if (
						($challenge->{type} =~ /^http-01$/ and $self->_httpCheck($_, $challenge->{token})) or
						($challenge->{type} =~ /^dns-01$/ and $self->_dnsCheck($_, $challenge->{token}))
					) {
						# Post challenge request
						my $res = $self->_post($challenge->{uri}, {resource => 'challenge', keyAuthorization => $challenge->{token}.'.'.$self->{account}{thumbprint}});

						# Handle error
						unless ($res->is_success) {
							confess 'POST '.$challenge->{uri}.' failed: '.$res->status_line;
						}

						# Extract content
						my $content = from_json($res->content);

						# Save if valid
						if ($content->{status} eq 'valid') {
							$self->{challenges}{$_}{status} = $content->{status};
						# Check is still polling
						} elsif ($content->{status} eq 'pending') {
							# Add to poll list for later use
							push(@{$self->{challenges}{$_}{polls}}, {
								type => (split(/-/, $challenge->{type}))[0],
								status => $content->{status},
								poll => $content->{uri}
							});
						}
					}
				}
			}
			# Check if check is challenge still in pending and no polls
			if ($self->{challenges}{$_}{status} eq 'pending' && scalar @{$self->{challenges}{$_}{polls}} == 0) {
				# Loop on all remaining challenges
				foreach my $challenge (@{$content->{challenges}}) {
					# Display help for http-01 check
					if ($challenge->{type} eq 'http-01') {
						print STDERR 'Create URI http://'.$_.'/.well-known/acme-challenge/'.$challenge->{token}.' with content '.$challenge->{token}.'.'.$self->{account}{thumbprint}."\n";
					# Display help for dns-01 check
					} elsif ($challenge->{type} eq 'dns-01') {
						print STDERR 'Create TXT record _acme-challenge.'.$_.'. with value '.(((sha256_base64($challenge->{token}.'.'.$self->{account}{thumbprint})) =~ s/=+\z//r) =~ tr[+/][-_]r)."\n";
					}
				}
			}
		}
	} @{$self->{domains}};

	# Init max run
	my $remaining = 10;

	# Poll pending
	while (--$remaining >= 0 and scalar map { $_->{status} eq 'valid' ? 1 : (); } values %{$self->{challenges}}) {
		# Sleep
		sleep(1);
		# Poll remaining pending
		map {
			# Init domain
			my $domain = $_;

			# Poll remaining polls
			map {
				# Create a request
				my $req = HTTP::Request->new(GET => $_->{poll});

				# Get request
				my $res = $ua->request($req);

				# Handle error
				unless ($res->is_success) {
					carp 'GET '.$self->{challenges}{$_}{http_challenge}.' failed: '.$res->status_line if ($self->{debug});
				}

				# Extract content
				my $content = from_json($res->content);

				# Save status
				if ($content->{status} ne 'pending') {
					$self->{challenges}{$domain}{status} = $content->{status};
				}
			} @{$self->{challenges}{$_}{polls}};
		} map { $self->{challenges}{$_}{status} eq 'pending' ? $_ : (); } keys %{$self->{challenges}};
	} 

	# Check if thumbprint is writeable
	if (-w $self->{config}{thumbprint}) {
		# Try to write thumbprint
		write_file($self->{config}{thumbprint}, '');
	}

	# Stop here with remaining chanllenge
	if (scalar map { ! defined $_->{status} or $_->{status} ne 'valid' ? 1 : (); } values %{$self->{challenges}}) {
		# Deactivate all activated domains 
		#XXX: not implemented by letsencrypt
		#map {
		#	# Post deactivation request
		#	my $res = $self->_post($self->{challenges}{$_}{http_uri}, {resource => 'authz', status => 'deactivated'});
		#	# Handle error
		#	unless ($res->is_success) {
		#		confess 'POST '.$self->{challenges}{$_}{http_uri}.' failed: '.$res->status_line;
		#	}
		#} map { $self->{challenges}{$_}{status} eq 'valid' ? $_ : () } keys %{$self->{challenges}};

		# Stop here as a domain of csr list failed authorization
		if ($self->{debug}) {
			my @domains = map { ! defined $self->{challenges}{$_}{status} or $self->{challenges}{$_}{status} ne 'valid' ? $_ : (); } keys %{$self->{challenges}};
			confess 'Fix the challenge'.(scalar @domains > 1?'s':'').' for domain'.(scalar @domains > 1?'s':'').': '.join(', ', @domains);
		} else {
			exit EXIT_FAILURE;
		}
	}
}

# Issue certificate
sub issue {
	my ($self) = @_;

	# Open csr file
	open(my $fh, '<', $self->{config}{pending}.'/'.$self->{mail}.'.'.($self->{domain}{prod} ? 'prod' : 'staging').'/'.REQUEST_CSR) or die $!;

	# Load csr
	my $csr = encode_base64url(join('', <$fh>) =~ s/^\0+//r);

	# Close csr file
	close($fh) or die $!;

	# Post certificate request
	my $res = $self->_post($self->{'new-cert'}, {resource => 'new-cert', csr => $csr});

	# Handle error
	unless ($res->is_success) {
		confess 'POST '.$self->{'new-cert'}.' failed: '.$res->status_line;
	}

	# Open crt file
	open($fh, '>', $self->{domain}{cert}) or die $!;

	# Convert to pem
	print $fh '-----BEGIN CERTIFICATE-----'."\n".encode_base64($res->content).'-----END CERTIFICATE-----'."\n";

	# Create a request
	my $req = HTTP::Request->new(GET => ACME_CERT);

	# Get request
	$res = $ua->request($req);

	# Handle error
	unless ($res->is_success) {
		carp 'GET '.ACME_CERT.' failed: '.$res->status_line if ($self->{debug});
	}

	# Append content
	print $fh $res->content;

	# Close file
	close($fh) or die $!;

	# Print success
	carp 'Success, pem certificate in '.$self->{domain}{cert} if ($self->{debug});
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
emailAddress			= __EMAIL_ADDRESS__

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

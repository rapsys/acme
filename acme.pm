# acme package
package acme;

# Best practice
use strict;
use warnings;

# Symbol export
use Exporter;
our @ISA = qw(Exporter);

# Load dependancies
use Carp qw(carp confess);
use Digest::SHA qw(sha256_base64);
use Email::Valid;
use File::Path qw(make_path);
use File::Temp; # qw( :seekable );
use IPC::System::Simple qw(capturex);
use JSON qw(encode_json decode_json);
use LWP;
use MIME::Base64 qw(encode_base64url encode_base64);
use Net::Domain::TLD;
use Tie::IxHash;
use POSIX qw(EXIT_FAILURE);

# Debug
use Data::Dumper;

# Documentation links
#XXX: see ietf draft at https://ietf-wg-acme.github.io/acme/
#XXX: see javascript implementation https://github.com/diafygi/gethttpsforfree/blob/gh-pages/js/index.js

# Set constants
use constant {
	DS => '/',

	CERT_DIR => 'cert',
	KEY_DIR => 'key',

	ACCOUNT_KEY => 'account.pem',
	ACCOUNT_PUB => 'account.pub',
	SERVER_KEY => 'server.pem',
	REQUEST_CSR => 'request.der',
	SERVER_CRT => 'server.crt',
	# rsa
	KEY_TYPE => 'rsa',
	# 2048|4096
	KEY_SIZE => 4096,

	ACME_DIR => 'https://acme-staging.api.letsencrypt.org/directory',
	#ACME_DIR => 'https://acme-v01.api.letsencrypt.org/directory',
	ACME_TERMS => 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf',

	VERSION => 'v0.1'
};

# User agent object
our $ua;

# Debug
our $_debug = 0;

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
	my ($class, $mail, @domains) = @_;

	# Create self hash
	my $self = {};

	# Link self to package
	bless($self, $class);

	# Add extra check to mail validity
	#XXX: mxcheck fail if there is only a A record on the domain
	my $ev = Email::Valid->new(-fqdn => 1, -tldcheck => 1, -mxcheck => 1);

	# Show error if check fail
	if (! defined $ev->address($mail)) {
		map { carp 'failed check: '.$_ if ($_debug) } $ev->details();
		confess 'Email::Valid->address failed';
	}

	# Save mail
	$self->{mail} = $mail;

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
	} @domains;

	# Save domains
	@{$self->{domains}} = @domains;

	# Return class reference
	return $self;
}

# Prepare environement
sub prepare {
	# Create all paths
	make_path(CERT_DIR, KEY_DIR, {error => \my $err});
	if (@$err) {
		map {
			my ($file, $msg) = %$_;
			carp ($file eq '' ? '' : $file.': ').$msg if ($_debug);
		} @$err;
		confess 'make_path failed';
	}

	# Create user agent
	$ua = LWP::UserAgent->new;
	$ua->agent(__PACKAGE__.'/'.VERSION)
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
	} (KEY_DIR.DS.ACCOUNT_KEY, KEY_DIR.DS.SERVER_KEY);

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
	} capturex('openssl', ('rsa', '-text', '-in', KEY_DIR.DS.ACCOUNT_KEY, '-noout', '-modulus'));

	# Drop stderr
	_dropStdErr();
	# Extract account public key
	$self->{account}{pubkey} = join('', map { chomp; $_; } capturex('openssl', ('rsa', '-in', KEY_DIR.DS.ACCOUNT_KEY, '-pubout')));
	# Restore stderr
	_restoreStdErr();

	# Store thumbprint
	#XXX: convert base64 to base64 url
	$self->{account}{thumbprint} = (sha256_base64(encode_json($self->{account}{jwk}{jwk})) =~ s/=+\z//r) =~ tr[+/][-_]r;
}

# Generate certificate request
sub genCsr {
	my ($self) = @_;

	# Openssl config template
	my $oct = File::Temp->new();

	# Load template from data
	map { s/__EMAIL_ADDRESS__/$self->{mail}/; s/__COMMON_NAME__/$self->{domains}[0]/; print $oct $_; } <DATA>;

	# Close data
	close(DATA);

	# Append domain names
	my $i = 1;
	map { print $oct 'DNS.'.$i++.' = '.$_."\n"; } @{$self->{domains}};

	# Generate csr
	capturex('openssl', ('req', '-new', '-outform', 'DER', '-key', KEY_DIR.DS.SERVER_KEY, '-config', $oct->filename, '-out', CERT_DIR.DS.REQUEST_CSR));

	# Close oct
	close($oct);
}

# Directory call
sub directory {
	my ($self) = @_;

	# Set time
	my $time = time;

	# Create a request
	my $req = HTTP::Request->new(GET => ACME_DIR.'?'.$time);

	# Get request
	my $res = $ua->request($req);

	# Handle error
	unless ($res->is_success) {
		confess 'GET '.ACME_DIR.'?'.$time.' failed: '.$res->status_line;
	}

	# Save nonce
	$self->{nonce} = $res->headers->{'replay-nonce'};

	# Merge uris in self content
	%$self = (%$self, %{decode_json($res->content)});
}

# Post request
sub _post {
	my ($self, $uri, $payload) = @_;

	# Protected field
	my $protected = encode_base64url(encode_json({nonce => $self->{nonce}}));

	# Payload field
	$payload = encode_base64url(encode_json($payload));

	# Sign temp file
	my $stf = File::Temp->new();

	# Append protect.payload to stf
	print $stf $protected.'.'.$payload;

	# Close stf
	close($stf);

	# Generate digest of stf
	my $signature = encode_base64url(join('', capturex('openssl', ('dgst', '-sha256', '-binary', '-sign', KEY_DIR.DS.ACCOUNT_KEY, $stf->filename))) =~ s/^\0+//r);

	# Create a request
	my $req = HTTP::Request->new(POST => $uri);
	
	# Set new-reg request content
	$req->content(encode_json({
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

# Get uri and check content
sub _httpCheck {
	my ($self, $uri, $content) = @_;

	# Create a request
	my $req = HTTP::Request->new(GET => $uri);

	# Get request
	my $res = $ua->request($req);

	# Handle error
	unless ($res->is_success) {
		carp 'GET '.$uri.' failed: '.$res->status_line if ($_debug);
		return;
	}

	# Handle invalid content
	unless($res->content =~ /^$content\s*$/) {
		carp 'GET '.$uri.' content match failed: /^'.$content.'\s*$/ !~ '.$res->content if ($_debug);
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
	my $res = $self->_post($self->{'new-reg'}, {resource => 'new-reg', contact => ['mailto:'.$self->{mail}], agreement => ACME_TERMS});

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
#TODO: implement combinations check one day
sub authorize {
	my ($self) = @_;

	# Create challenges hash
	%{$self->{challenges}} = ();

	# Pending list
	my @pending = ();

	# Create request for each domain
	map {
		# Post new-authz request
		my $res = $self->_post($self->{'new-authz'}, {resource => 'new-authz', identifier => {type => 'dns', value => $_}, existing => 'accept'});

		# Handle error
		unless ($res->is_success) {
			confess 'POST '.$self->{'new-authz'}.' for '.$_.' failed: '.$res->status_line;
		}

		# Decode content
		my $content = decode_json($res->content);

		# Check domain
		unless (defined $content->{identifier}{value} && $content->{identifier}{value} eq $_) {
			confess 'domain matching '.$content->{identifier}{value}.' for '.$_.' failed: '.$res->status_line;
		}

		# Check status
		unless ($content->{status} eq 'valid' or $content->{status} eq 'pending') {
			confess 'POST '.$self->{'new-authz'}.' for '.$_.' failed: '.$res->status_line;
		}

		# Add challenge
		%{$self->{challenges}{$_}} = (
			status => undef,
			expires => undef,
			#dns_uri => undef,
			#dns_token => undef,
			http_uri => undef,
			http_token => undef,
			http_challenge => undef
		);

		# Save status
		$self->{challenges}{$_}{status} = $content->{status};

		# Save pending data
		if ($content->{status} eq 'pending') {
			# Exctract validation data
			foreach my $challenge (@{$content->{challenges}}) {
				if ($challenge->{type} eq 'http-01') {
					$self->{challenges}{$_}{http_uri} = $challenge->{uri};
					$self->{challenges}{$_}{http_token} = $challenge->{token};
				#} elsif ($challenge->{type} eq 'dns-01') {
				#	$self->{challenges}{$_}{dns_uri} = $challenge->{uri};
				#	$self->{challenges}{$_}{dns_token} = $challenge->{token};
				}
			}

			# Check dns challenge
			#XXX: disabled for now
			#$self->_dnsCheck('_acme-challenge.'.$_.'.', $self->{challenges}{$_}{http_token}.'.'.$self->{account}{thumbprint});

			# Check http challenge
			if ($self->_httpCheck(
				# Well known uri
				'http://'.$_.'/.well-known/acme-challenge/'.$self->{challenges}{$_}{http_token},
				# token.thumbprint
				$self->{challenges}{$_}{http_token}.'.'.$self->{account}{thumbprint}
			)) {
				# Post challenge request
				my $res = $self->_post($self->{challenges}{$_}{http_uri}, {resource => 'challenge', keyAuthorization => $self->{challenges}{$_}{http_token}.'.'.$self->{account}{thumbprint}});

				# Handle error
				unless ($res->is_success) {
					confess 'POST '.$self->{challenges}{$_}{http_uri}.' failed: '.$res->status_line;
				}

				# Extract content
				my $content = decode_json($res->content);

				# Save status
				$self->{challenges}{$_}{status} = $content->{status};

				# Add challenge uri to poll
				#XXX: in case it is still pending
				if ($content->{status} eq 'pending') {
					$self->{challenges}{$_}{http_challenge} = $content->{uri};
				}
			} else {
				# Set failed status
				$self->{challenges}{$_}{status} = 'invalid';

				# Display challenge to fix
				print STDERR 'Makes http://'.$_.'/.well-known/acme-challenge/'.$self->{challenges}{$_}{http_token}.' return '.$self->{challenges}{$_}{http_token}.'.'.$self->{account}{thumbprint}."\n";
			}
		}
	} @{$self->{domains}};

	# Poll pending
	while (scalar map { $_->{status} eq 'pending' ? 1 : (); } values %{$self->{challenges}}) {
		# Sleep
		sleep(1);
		# Poll remaining pending
		map {
			# Create a request
			my $req = HTTP::Request->new(GET => $self->{challenges}{$_}{http_challenge});

			# Get request
			my $res = $ua->request($req);

			# Handle error
			unless ($res->is_success) {
				carp 'GET '.$self->{challenges}{$_}{http_challenge}.' failed: '.$res->status_line if ($_debug);
			}

			# Extract content
			my $content = decode_json($res->content);

			# Save status
			$self->{challenges}{$_}{status} = $content->{status};
		} map { $self->{challenges}{$_}{status} eq 'pending' ? $_ : (); } keys %{$self->{challenges}};
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
		#		print Dumper($res);
		#		confess 'POST '.$self->{challenges}{$_}{http_uri}.' failed: '.$res->status_line;
		#	}
		#} map { $self->{challenges}{$_}{status} eq 'valid' ? $_ : () } keys %{$self->{challenges}};

		# Stop here as a domain of csr list failed authorization
		if ($_debug) {
			confess 'Fix the challenges for domains: '.join(', ', map { ! defined $self->{challenges}{$_}{status} or $self->{challenges}{$_}{status} ne 'valid' ? $_ : (); } keys %{$self->{challenges}});
		} else {
			exit EXIT_FAILURE;
		}
	}
}

# Issue certificate
sub issue {
	my ($self) = @_;

	# Open csr file
	open(my $fh, '<', CERT_DIR.DS.REQUEST_CSR) or die $!;

	# Load csr
	my $csr = encode_base64url(join('', <$fh>) =~ s/^\0+//r);

	# Close csr file
	close($fh) or die $!;

	# Post certificate request
	my $res = $self->_post($self->{'new-cert'}, {resource => 'new-cert', csr => $csr});

	# Handle error
	unless ($res->is_success) {
		print Dumper($res);
		confess 'POST '.$self->{'new-cert'}.' failed: '.$res->status_line;
	}

	# Open crt file
	open($fh, '>', CERT_DIR.DS.SERVER_CRT) or die $!;
	# Convert to pem
	print $fh '-----BEGIN CERTIFICATE-----'."\n".encode_base64($res->content).'-----END CERTIFICATE-----'."\n";
	#TODO: merge https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem here
	# Close file
	close($fh) or die $!;

	# Print success
	carp 'Success, pem certificate in '.CERT_DIR.DS.SERVER_CRT if ($_debug);
}

# Resolve dns and check content
#XXX: this can't work without a plugin in dns to generate signature from token.thumbprint and store it in zone
#XXX: each identifier authorisation generate a new token, it's not possible to do a yescard answer
#XXX: the digest can be bigger than 255 TXT record limit and well known dns server will randomize TXT record order
#
#XXX: conclusion disabled for now
sub _dnsCheck {
	my ($self, $domain, $content) = @_;

	# Sign temp file
	my $stf = File::Temp->new();

	# Append protect.payload to stf
	print $stf $content;

	# Close stf
	close($stf);

	# Generate digest of stf
	my $signature = encode_base64url(join('', capturex('openssl', ('dgst', '-sha256', '-binary', '-sign', KEY_DIR.DS.ACCOUNT_KEY, $stf->filename))));

	# Create resolver
	my $res = new Net::DNS::Resolver();

	# Check if we get dns answer
	unless(my $rep = $res->search($domain, 'TXT')) {
		carp 'search TXT record for '.$domain.' failed' if ($_debug);
		return;
	} else {
		unless (scalar map { $_->type eq 'TXT' && $_->txtdata =~ /^$signature$/ ? 1 : (); } $rep->answer) {
			carp 'search recursively TXT record for '.$_.' failed' if ($_debug);
			return;
		}
	}

	return 1;
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

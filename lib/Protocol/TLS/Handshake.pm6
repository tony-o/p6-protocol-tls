use Protocol::TLS::Trace;
use Protocol::TLS::Constants;

my %handshake-types =
  HSTYPE_HELLO_REQUEST       => 'hello_request',
  HSTYPE_CLIENT_HELLO        => 'client_hello',
  HSTYPE_SERVER_HELLO        => 'server_hello',
  HSTYPE_CERTIFICATE         => 'certificate',
  HSTYPE_SERVER_KEY_EXCHANGE => 'server_key_exchange',
  HSTYPE_CERTIFICATE_REQUEST => 'certificate_request',
  HSTYPE_SERVER_HELLO_DONE   => 'server_hello_done',
  HSTYPE_CERTIFICATE_VERIFY  => 'certificate_verify',
  HSTYPE_CLIENT_KEY_EXCHANGE => 'client_key_exchange',
  HSTYPE_FINISHED            => 'finished',
;

my %decoder = 
  %handshake-types.keys.map({ 
    $_ => %handshake-types{$_} ~ '_decode';
  })
;

my %encoder = 
  %handshake-types.keys.map({ 
    $_ => %handshake-types{$_} ~ '_encode';
  })
;

class Protocol::TLS::Handshake {
  method new {!!!};
  method decode($ctx, Buf $buf is rw, Int $offset, Int $length) {
    return 0 if $buf.elems - $offset < 4;
    my ($type, $len-high, $len-low) = $buf.unpack("x{$offset}CCn");
    if $len-high * 256**3 + $len-low != $length - 4 {
      $.tracer.debug("Incorrect handshake record length: { $len-high * 256**3 + $len-low } (expected $length)\n");
      $ctx.error(DECODE_ERROR);
      return Mu;
    }
    if !%handshake-types.exists_key($type) {
      $.tracer.debug("Unknown handshake type: $type\n");
      $ctx.error(DECODE_ERROR);
      return Mu;
    }
    $.tracer.debug("Got {Protocol::TLS::Constants.const-name('hs_types', $type)}\n");

    my $len = %decoder{$type}.($ctx, $buf, $offset+4, $length-4);
    $ctx.pending<hs_messages>.push($buf[$offset .. $length]) if $type != HSTYPE_HELLO_REQUEST;

    $ctx.state-machine('recv', CTYPE_HANDSHAKE, $type);
    return $length;
  }

  method encode($ctx, $type, *@s) {
    my $encoded = pack('CC n/a*', $type, 0, %encoder{$type}.($ctx, |@s));
    $ctx.pending<hs_messages>.push($encoded) if $type != HSTYPE_HELLO_REQUEST;
    $encoded;
  }

  method hello_request_decode { 0; }
  method hello_request_encode { 0; }

  method client_hello_decode($ctx, Buf $buf is rw, Int $offset, Int $length) {
    my ($tls-version, $random, $session-id, $ciphers-l) =
      $buf.unpack("x{$offset} na32 C/a n");
    my $sess-l = $session-id.chars || 0;
    if $sess-l > 32 {
      $.tracer.debug("Session-id length error: $sess-l\n");
      $ctx.error(DECODE_ERROR);
      return Mu;
    }
    if !$ciphers-l || $ciphers-l % 2 {
      $.tracer.debug("Cipher suites length error\n");
      $ctx.error(DECODE_ERROR);
      return Mu;
    }
    my $offs = 37 + $sess-l;
    my @ciphers = $buf.unpack("x{$offset+$offs}n{$ciphers-l / 2}");
    $offs += $ciphers-l;
    my @compr   = $buf.unpack("x{$offset+$offs}C/C*");
    if !@compr.elems {
      $.tracer.debug("Compression methods not defined\n");
      $ctx.error(DECODE_ERROR);
      return Mu;
    }
    $offs += 1 + @compr.elems;

    my $ext_result;
    if $length > $offs {
      my $len = $ctx.ext-decode(
        $ext_result, $buf, $offset + $offs, $length - $offs
      );
      return Mu unless defined $len;
      $offs += $len;
    }
    my $res = $ctx.validate-client-hello(
      ciphers     => @ciphers,
      compression => @compr,
      tls_version => $tls-version,
      random      => $random,
      extensions  => $ext_result,
    );
    return $res ?? $offs !! Mu;
  }

  method server-hello-decode($ctx, Buf $buf, Int $offset, Int $length) {
    my ($version, $rand, $sess-id, $cipher, $compr) =
      $buf.unpack("x$offset n a32 C/a n C");
    my $offs = 35 + $sess-id.chars + 2 + 1;
    my $ext_result;
    if $length > $offs {
      my $len = $ctx.ext-decode(
        $ext_result, $buf, $offset + $offs, $length - $offs
      );
      return Mu unless defined $len;
      $offs += $len;
    }
    my $res = $ctx.validate-server-hello(
      cipher      => $cipher,
      compression => $compr,
      session_id  => $sess-id,
      version     => $version,
      random      => $rand,
      extensions  => $ext_result,
    );
    return $res ?? $offs !! Mu;
  }

  method server-hello-encode($ctx, %data) {
    my $ext = '';
    if %data<extensions> // False {

    }
    
    pack("n a32 C/a* n C", "{%data<tls_version>}{%data<server_random>}{%data<session_id>}" ~
      "{%data<cipher>}{%data<compression>}")
      ~ $ext;
  }

  method certificate-decode($ctx, $buf, $offset, $length) {
    my $list-len = Buf.new(0, $buf[$offset .. $offset+3].contents).unpack('N');
    my $offs = 3;
    if $list-len > $length - $offs {
      $.tracer.debug("list too long: $list-len\n");
      $ctx.error(DECODE_ERROR);
      return Mu;
    }
    while $offs < $list-len {
      my $cert-len = Buf.new(0, $buf[$offset+$offs .. $offset+$offs+3].contents).unpack('N');
      if $cert-len > $length - $offs - 3 {
        $.tracer.debug("cert length too long: $cert-len\n");
        $ctx.error(DECODE_ERROR);
        return Mu;
      }
      $ctx.pending<cert> ||= [];
      $ctx.pending<cert>.push($buf[$offset+$offs+3, $offset+$offs+3+$cert-len]);
      $offs += 3 + $cert-len;
    }

    return $offs;
  }

  method certificate-encode($ctx, *@s) {
    my $res = Buf.new;
    for @s -> $cert {
      $res ~= pack('C n/a*', 0, $cert);
    }
    Buf.new(0, $res.elems).pack('Cn') ~ $res;
  }

  method server-key-exchange-decode { die 'not implemented'; }
  method server-key-exchange-encode { die 'not implemented'; }
  method certificate-request-decode { die 'not implemented'; }
  method certificate-request-encode { die 'not implemented'; }
  method server-hello-done-decode   { 0  };
  method server-hello-done-encode   { '' };
  method certificate-verify         { die 'not implemented'; }

  method client-key-exchange-decode($ctx, Buf $buf, Int $offset, Int $length) {
    my ($encoded-pkey) = $buf.unpack("x{$offset} n/a");
    unless defined $encoded-pkey && $encoded-pkey.chars == $length - 2 {
      $.tracer.error("broken key length: {$length - 2} vs {$encoded-pkey.chars || 0 }\n");
      $ctx.error(DECODE_ERROR);
      return Mu;
    }
    unless $ctx.validate-client-key($encoded-pkey) {
      $.tracer.error("client key validation failed\n");
      $ctx.error(DECODE_ERROR);
      return Mu;
    }
    $length;
  }

  method client-key-exchange-encode($buf) {
    pack('n/a*', $buf); 
  }

  method finished-encode($o) { $o; }
  method finished-decode($ctx, Buf $buf, $offset, $length) {
    my $message = $buf[$offset .. $offset+$length];
    return $ctx.validate-finished($message) ?? $length !! Mu;
  }
#line 245
}

use Protocol::TLS::Trace;
use Protocol::TLS::RecordLayer;
use Protocol::TLS::Extension;
use Protocol::TLS::Crypto;
use Protocol::TLS::Constants;

my %sp = 
  connectionEnd       => undef,      # CLIENT, SERVER
  PRFAlgorithm        => undef,      # tls_prf_sha256
  BulkCipherAlgorithm => undef,      # null, rc4, 3des, aes
  CipherType          => undef,      # stream, block, aead
  enc_key_length      => undef,
  block_length        => undef,
  fixed_iv_length     => undef,
  record_iv_length    => undef,
  MACAlgorithm        => undef,      # sha1, sha256
  mac_length          => undef,
  mac_key_length      => undef,
  CompressionMethod   => undef,      # null
  master_secret       => ' ' x 48,
  client_random       => ' ' x 32,
  server_random       => ' ' x 32,
;

my %kb =
  client_write_MAC_key        => undef,
  server_write_MAC_key        => undef,
  client_write_encryption_key => undef,
  server_write_encryption_key => undef,
  client_write_IV             => undef,
  server_write_IV             => undef,
;

class Protocol::TLS::Context {
  has $.type;
  has Protocol::TLS::Crypto $crypto .= new;
  has $.proposed;
  has $.pending;
  has $.current-decode;
  has $.current-encode;
  has $.session-id;
  has $.tls-version;
  has $.seq-read;
  has $.seq-write;
  has $.queue = Array.new;
  has $.error-msg;
  has $.state-msg = STATE_IDLE;
  has $.shutdown = 0;
  has $.cb    = Array.new;

  method copy-pending {
    my $copy = %(
      cipher            => $.pending<cipher>,
      securityParamters => %( $.pending<securityParameters> ),
      tls-version       => $.pending<tls-version>,
      session-id        => $.pending<session-id>,
      compression       => $.pending<compression>,
    );
    $copy<securityParameters>.delete_key('client_random');
    $copy<securityParameters>.delete_key('server_random');
    $copy;
  }
  method clear-pending {
    $.pending = %(
      securityParameters = {%sp},
      key-block          = {%kb},
      tls-version        = Nil,
      session-id         = Nil,
      cipher             = Nil,
      hs-messages        = Array.new,
      compression        = Nil,
    );
    $.pending<securityParameters><connectionEnd> = $.type;
  }
  multi method BUILD {
    $.clear-pending; 
    $.load-extensions('ServerName');
    $.pending<securityParameters>{$.type == SERVER ??
      'server_random' !! 'client_random' } = pack('N', time) . $.crypto.random(28); 
  }
  method error(*@args) {
    $.tracer.debug("called error: {@args.perl}\n");
    if @args.elems && !$.shutdown {
      $.error-msg = @args[0];
      $.on-error.($.error-msg) if $.on-error;
      $.finish; 
    }
    $.error-msg;
  }
  method finish {
    $.enqueue(CTYPE_ALERT, FATAL, $.error) unless $.shutdown;
    $.shutdown = 1;
  }
  method close {
    $.enqueue(CTYPE_ALERT, FATAL, CLOSE_NOTIFY) unless $.shutdown;
    $.shutdown = 1; 
  }
  method enqueue(*@records) {
    for @records -> ($a,$b,$c) {
      $.tracer.debug("enqueue {Protocol::TLS::Constants.const_name('c_types', $a)} {$a == CTYPE_HANDSHAKE ?? '/' ~ Protocol::TLS::Constants.const_name('hs_types', $b) !! ''}\n");
      $.queue.push($.record-encode(TLS_v12, [$a,$b,$c])); 
      $.state-machine('send', $a, $a == CTYPE_HANDSHAKE ?? $b !! Array.new);
    }
  }
  method dequeue {
    $.queue.shift;
  }
  method send($data) {
    if $.state = STATE_OPEN {
      $.enqueue([CTYPE_APPLICATION_DATA, $data]);
    }
  }
  method state-machine($action, $c-type, $hs-type) {
    my $prev-state = $.state;
    if $c-type == CTYPE_ALERT { 
    } elsif $c-type == CTYPE_APPLICATION_DATA {
      if $prev-state != STATE_OPEN {
        $.tracer.error("Handshake was not complete\n");
        $.error(UNEXPECTED_MESSAGE);
      }
    } elsif $c-type == STATE_IDLE {
      if $c-type != CTYPE_HANDSHAKE && $hs-type != HSTYPE_CLIENT_HELLO {
        $.tracer.error("Only ClientHello allowed in IDLE state\n");
        $.error(UNEXPECTED_MESSAGE);
      } else {
        $.state(STATE_HS_START);
      }
    } elsif $prev-state == STATE_HS_START {
      if $c-type != CTYPE_HANDSHAKE && $hs-type != HSTYPE_SERVER_HELLO {
        $.tracer.error("Only ServerHello allowed at handshake start state\n");
        $.error(UNEXPECTED_MESSAGE);
      } elsif $.proposed<session-id> // False eq $.pending<session-id> {
        $.state(STATE_SESS_RESUME);
      } else {
        $.state(STATE_SESS_NEW);
      }
    } elsif $prev-state == STATE_SESS_RESUME {
      if $c-type == CTYPE_HANDSHAKE {
        if $hs-type == HSTYPE_FINISHED {
          $.state(STATE_HS_RESUME);
        }
      } elsif $c-type == CTYPE_CHANGE_CIPHER_SPEC {
        $.change-cipher-spec($action);
      } else {
        $.tracer.error("Unexpected handshake type\n");
        $.error(UNEXPECTED_MESSAGE);
      }
    } elsif $prev-state == STATE_HS_RESUME {
      if $c-type == CTYPE_HANDSHAKE && $hs-type == HSTYPE_FINISHED {
        $.state(STATE_OPEN);
      } elsif $c-type == CTYPE_CHANGE_CIPHER_SPEC {
        $.change-cipher-spec($action);
      } else{
        $.tracer.error("Unexpected handshake type\n");
        $.error(UNEXPECTED_MESSAGE);
      }
    } elsif $prev-state == STATE_SESS_NEW {
      if $c-type == CTYPE_HANDSHAKE {
        if $hs-type == HSTYPE_SERVER_HELLO_DONE {
          $.state(STATE_HS_HALF);
        }
      } else {
        $.tracer.error("Unexpected handshake type\n");
        $.error(UNEXPECTED_HANDSHAKE);
      }
    } elsif $prev-state == STATE_HS_HALF {
      if $c-type == CTYPE_HANDSHAKE {
          if $hs-type == HSTYPE_FINISHED {
            $.state(STAT_HS_FULL);
          } 
      } elsif $c-type == CTYPE_CHANGE_CIPHER_SPEC {
        $.change-cipher-spec($action);
      } else {
        $.tracer.error("Unexpected handshake type\n");
        $.error(UNEXPECTED_MESSAGE);
      }
    } elsif $prev-state == STATE_HS_FULL {
      if $c-type == CTYPE_HANDSHAKE {
        if $hs-type == HSTYPE_FINISHED {
          $.state(STATE_OPEN);
        }
      } elsif $c-type == CTYPE_CHANGE_CIPHER_SPEC {
        $.change-cipher-spec($action);
      } else {
        $.tracer.error("Unexpected handshake type\n");
        $.error(UNEXPECTED_MESSAGE);
      }
    } elsif $p-state == STATE_OPEN {
      $.tracer.warning("ReNegotiation not supported yet\n");
    }
  }

  method generate-key-block {
    my $sp = $.pending<securityParameters>;
    my $kb = $.pending<key_block>;
    my $da;
    ($da, $sp<BulkCipherAlgorithm>, $sp<MACAlgorithm>) = Protocol::TLS::Constants.cipher-type($.pending<cipher>);
    
    $.tracer.debug("Generating key block for cipher {Protocol::TLS::Constants.const-name($.pending<cipher>)}");
    $sp<mac_length> = $sp<mac_key_length> = 
      $sp<MACAlgorithm> eq 'SHA'    ?? 20 !!
      $sp<MACAlgorithm> eq 'SHA256' ?? 32 !!
      $sp<MACAlgorithm> eq 'MD5'    ?? 16 !!
                                       0;

    ($sp<CipherType>, $sp<enc_key_length>, $sp<fixed_iv_length>, $sp<block_length>) = 
      $sp<BulkCipherAlgorithm> eq 'AES_128_CBC'  ?? ('block',  16, 16,  16) !!
      $sp<BulkCipherAlgorithm> eq 'AES_256_CBC'  ?? ('block',  32, 16,  16) !!
      $sp<BulkCipherAlgorithm> eq '3DES_EDE_CBC' ?? ('block',  24,  8,   8) !!
      $sp<BulkCipherAlgorithm> eq 'RC4_128'      ?? ('stream', 16,  0, Nil) !!
                                                    ('stream',  0,  0, Nil);

    ($kb<client_write_MAC_key>, $kb<server_write_MAC_key>, $kb<client_write_encryption_key>, $kb<server_write_encryption_key>,
     $kb<client_write_IV>,      $kb<server_write_IV>) = $.crypto.PRF(
                                                          $sp<master_secret>,
                                                          'key expansion',
                                                          $sp<server_random> ~ $sp<client_random>,
                                                          $sp<mac_key_length> * 2 + 
                                                          $sp<enc_key_length> * 2 +
                                                          $sp<fixed_iv_length> * 2
                                                        ).unpack(sprintf('a%i' x 6, ( $sp<mac_key_length> ) x 2, ( $sp<enc_key_length> ) x 2, ( $sp<fixed_iv_length> ) x 2));
  
    ();
  }

  method change-cipher-spec($action) {
    $.tracer.debug("Apply cipher spec $action...\n");
    my ($sp, $kb) = ($.pending<securityParameters>, $.pending<key_block>);
    $.generate-key-block unless defined $kb<client_write_MAC_key>;
    my $cur = $action eq 'recv' ?? $.current_decode !! $.current_encode;
    for $sp.keys -> $k {
      $cur<securityParameters>{$k} = $sp{$k};
    }
    for $kb.keys -> $k {
      $cur<key_block>{$k} = $kb{$k};
    }
  }

  method state(*@args) {
    for @args.elems -> $arg {
      $.on-change-state.(self, $.state-msg, $arg) if $.on-change-state // False;
      $.state-msg = $arg;

      if $.cb // False && $.cb{$arg} // False {
        for @($.cb{$arg}) -> $cb {
          $.cb.(self);
        }
      }
    }
    $.state-msg;
  }

  method state-cb($state, $cb) {
    $.cb{$state}.push($cb);
  }

  method validate-server-hello(*%h) {
    my $tls_v = Protocol::TLS::Constants.is_tls_version(%h<version>);
    if $tls_v // False {
      $.tracer.error("Server TLS version %h<version> not recognized\n");
      $.error(HANDSHAKE_FAILURE);
      return Nil;
    }
    my $p = $.pending;
    my $r = $.proposed;
    if $tls_v < $r<tls_version> {
      $.tracer.error("Server TLS version $tls_v is not supported\n");
      $.error(PROTOCOL_VERSION);
      return Nil;
    }
    if ($r<compression>.grep({ %h<compression> == * })).elems == 0 {
      $.tracer.error("Server compression not supported\n");
      $.error(HANDSHAKE_FAILURE);
      return Nil;
    }
    if ($r<ciphers>.grep({ %h<cipher> == * })).elems == 0 {
      $.tracer.error("Server cipher not accepted\n");
      $.error(HANDSHAKE_FAILURE);
      return Nil;
    }
    $p<tls_version>                           = $tls_v;
    $p<securityParameters><server_random>     = $h<random>;
    $p<session_id>                            = $h<session_id>;
    $p<securityParameters><CompressionMethod> = $p<compression> = $h<compression>;
    $p<cipher>                                = $h<cipher>;
  }

  method validate-client-hello(*%h) {
    my $tls_v = Protocol::TLS::Constants.is_tls_version(%h<version>);
    if $tls_v // False {
      $.tracer.error("Client's TLS version %h<version> not recognized\n");
      $.error(HANDSHAKE_FAILURE);
      return Nil;
    }
    my $p = $.pending;
    my $r = $.proposed;
    if $tls_v < $r<tls_version> {
      $.tracer.error("Server TLS version $tls_v is not supported\n");
      $.error(PROTOCOL_VERSION);
      return Nil;
    }
    for @($pro<compression>) -> $c {
      next unless @(%h<compression>).grep({ $c == * });
      $p<securityParameters><CompressionMethod> = $c;
      last;
    }
    if not ($p<securityParameters><CompressionMethod> // False) {
      $.tracer.error("Client's compression not supported\n");
      $.error(HANDSHAKE_FAILURE);
      return Nil;
    }
    $p<tls_version>                       = $tls_v;
    $p<securityParameters><client_random> = %h<random>;
    $p<session_id>                        = %h<session_id>;
       
    if not ($p<cipher> // False) {
      $.tracer.error("Client's cipher not supported\n");
      $.error(HANDSHAKE_FAILURE);
      return Nil;
    }
    1;
  }

  method peer-finished {
    $!finished( $.type == CLIENT ?? SERVER !! CLIENT );
  }

  method finished {
    $!finished( $.type == CLIENT ?? CLIENT !! SERVER );
  }

  method !finished($type) {
    $.crypto.PRF(
      $.pending<securityParameters><master_secret>,
      ($.type  == CLIENT ?? 'client' !! 'server') ~ ' finished',
      $.crypto.PRF-hash(@($.pending<hs_messages>).join('')),
      12,
    );
  }

  method validate-finished($msg) {
    my $p   = $.pending;
    my $sp  = $.p<securityParameters>;
    my $fin = $.peer_finished;
    $.tracer.debug("finished expected: " ~ $.tracer.bin2hex($fin));
    $.tracer.debug("finished received: " ~ $.tracer.bin2hex($msg));
    if $fin ne $msg {
      $.tracer.error("Finished not match\n");
      $.error(HANDSHAKE_FAILURE);
      return Nil;
    }
    1;
  }
}

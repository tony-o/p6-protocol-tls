use Protocol::TLS::Constants;
use Protocol::TLS::Trace;

class Protocol::TLS::Protection {
  method decode($ctx, $type, $version, Buf $buf, $offset, $length) {
    my $sp = $ctx.current_decode<securityParameters>;
    my $kb = $ctx.current_decode<key_block>;

    my $crypto = $ctx.crypto;
    my $res;

    my ($mkey, $ckey, $iv) = !defined $sp ?? () !!
                             $sp<connectionEnd> == SERVER ?? (
                               $kb<client_write_MAC_key>,
                               $kb<client_write_encryption_key>,
                               $kb<client_write_IV>,
                             ) !!
                             (
                               $kb<server_write_MAC_key>,
                               $kb<server_write_encryption_key>,
                               $kb<server_write_IV>,
                             ); 

    if defined $ckey && $ckey.elems {
      if $length < $sp<fixed_iv_length> + $sp<block_length> {
        $.tracer.debug("too short ciphertext: $length\n");
        return Mu;
      }
      my $iv = $buf[$offset .. $offset+$sp<fixed_iv_length>];
      $res = $crypto.CBC_decode(
        $sp<BulkCipherAlgorithm>,
        $ckey,
        $iv,
        $buf[$offset+$sp<fixed_iv_length> .. $offset+$sp<fixed_iv_length>+$length-$sp<fixed_iv_length>]
      );
      my $pad-len = $res[*-1].pack('C');
      if $pad-len >= $length + 1 + $sp<mac_length> {
        $.tracer.error("Padding length $pad-len too long");
        return Mu;
      }
      my $pad = $res[*-$pad-len - 1];
    }

    if defined $mkey && $mkey.elems {
      unless defined $res {
        $res = $buf[$offset .. $offset+$length];
      }

      my $mac        = $res[*-$sp<mac_length>];
      my $seq        = $ctx.seq_read++;
      my $mac-origin = $crypto.MAC(
        $sp<MACAlgorithm>, 
        $mkey, 
        pack('N2Cn2', 0, $seq, $type, $version, $res.elems) ~ $res
      );

      if $mac ne $mac-origin {
        $.tracer.error("error in comparing MAC\n");
        $.tracer.debug("{Protocol::TLS::Constants.const_name('c_types', $type)} "
          ~ " <- type of broken packet.\nLength {$length}\nmkey: {Protocol::TLS::Constants.bin2hex($mkey)}\n"
          ~ "mac: {Protocol::TLS::Constants.bin2hex($mac)}\nmac_origin: {Protocol::TLS::Constants.bin2hex($mac-origin)}\n");
        $ctx.error(BAD_RECORD_MAC);
        return Mu;
      }
    }
    $res ?? $res !! $buf[$offset .. $offset+$length];
  }

  method encode($ctx, $version, $type, $payload) {
    my $sp     = $ctx.current_encode<securityParameters>;
    my $kb     = $ctx.current_encode<key_block>;
    my $crypto = $ctx.crypto;

    my ($mkey, $ckey, $iv) = 
      !defined $sp ?? 
        () !!
      $sp<connectionEnd> == CLIENT ??
        ($kb<client_write_MAC_key>,$kb<client_write_encryption_key>,$kb<client_write_IV>) !!
      ($kb<server_write_MAC_key>,$kb<server_write_encryption_key>,$kb<server_write_IV>);
    my ($mac, $res) = ('') x 2;

    if defined $mkey && $mkey.elems {
      my $seq = $ctx.seq_write++;
      $mac = $crypto.MAC($sp<MACAlgorithm>, $mkey, 
        pack('N2Cn2',0,$seq,$type,$version,$payload.elems) ~ $payload
      );
    }
    if defined $ckey && $ckey.elems {
      if $sp<CipherType> eq 'block' {
        my $pad-len = $sp<block_length> - ( ( $payload.elems + $mac.elems + 1 ) % $sp<block_length> );
        my $iv      = $crypto.random($sp<fixed_iv_length>);
        $res        = $iv
          ~ $crypto.CBC-encode($sp<BulkCipherAlgorithm>, $ckey, $iv, $payload ~ $mac ~ pack('C', $pad-len) x ($pad-len + 1));


      } else {
        die "Cipher type $sp<CipherType> not implemented";
      }
    }
    $res ?? $res !! $payload ~ $mac;
  }
}

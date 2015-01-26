use Protocol::TLS::Tracer;

class Protocol::TLS::Extension {
  has Protocol::TLS::Tracer $.tracer .= instance;

  method ext_decode($ctx, $result, Buf $buf, Int $offset, Int $len) {
    if $len < 2 {
      $.tracer.debug("Extensions length error: MUST be at least 2 bytes\n");
      $ctx.error();
      return Nil;
    }
    my $ext_l = $buf[$offset .. $offset+2].unpack('n');
    my $o     = 2;
    if $o + $ext_l > $len {
      $.tracer.debug("Extensions length error: $ext_l\n");
      $ctx.error();
      return Nil; 
    }
    while $o + 4 < $len {
      my ($type, $l) = $buf[$offset+$o .. $offset+$o+4].unpack('n2');
      $o += 4;

      if $o + $l > $len {
        $.tracer.debug("Extensions $type length error: $l\n");
        $ctx.error();
        return Nil;
      }

      if $ctx<extensions>{$type} // False {
        $ctx<extensions>{$type}.decode($ctx, $result.type, $buf, $offset + $o, $l);
      }
      $o += $l;
    }

    return $o;
  }

  method ext_encode {
    die 'Unimplemented';
  }

  method load_extensions($ctx, *@ext) {
    for @ext -> $ext {
      my $m = 'Protocol::TLS::Extension::' ~ $ext;
      require($m);
      $ctx.extensions{$m<type>} = $m.new;
    }
  }
}

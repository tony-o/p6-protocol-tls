use Protocol::TLS::Trace;
use Protocol::TLS::Constants;

class Protocol::TLS::ChangeCipherSpec {
  method new {!!!};
  method decode($ctx, Buf $buf, Int $offset, Int $len) {
    return 0 if $buf.elems - $offset < 1;
    my ($type) = $buf.unpack("x{$offset}C");
    return Nil unless $type == 1 && $len == 1;

    $ctx.state-machine('recv', CTYPE_CHANGE_CIPHER_SPEC, 1);
    1;
  }
  method encode {
    1.chr;
  }
}

use Protocol::TLS::Trace;
use Protocol::TLS::Constants;
use Protocol::TLS::ChangeCipherSpec;
use Protocol::TLS::Handshake;
use Protocol::TLS::Alert;
use Protocol::TLS::Application;
use Protocol::TLS::Compression;
use Protocol::TLS::Protection;

my %content-types = 
  CTYPE_CHANGE_CIPHER_SPEC => 'ChangeCipherSpec',
  CTYPE_ALERT              => 'Alert',
  CTYPE_HANDSHAKE          => 'Handshake',
  CTYPE_APPLICATION_DATA   => 'Application',
;

my %decoder =
  %content-types.keys.map({
    $_ => "Protocol::TLS::{%content-types{$_}}::decode"
  })
;

my %encoder =
  %content-types.keys.map({
    $_ => "Protocol::TLS::{%content-types{$_}}::encode"
  })
;

class Protocol::TLS::RecordLayer {
  has Protocol::TLS::Trace $.tracer = &Protocol::TLS::Trace::instance;
  method new {!!!};
  method record-decode($ctx, Buf $buf, Int $offset) {
    return 0 if $buf.elems - $offset < 5;
    my ($type, $version, $length) = $buf.unpack("x{$offset}Cn2");

    if Protocol::TLS::Constants.is-tls-version($version) {
      $.tracer.debug(sprintf("Unsupported TLS version: %i.%i\n", ($version/256).Int, $version % 256));
      $ctx.error;
      return Mu;
    }

    if ! %content-types.exists_key($type) {
      $.tracer.debug("Unknown content type: $type\n");
      $ctx.error;
      return Mu;
    }

    return 0 if $buf.elems - $offset - 5 - $length < 0;

    my $decrypted = Protocol::TLS::Protection::decode($ctx, $type, $version, $buf, $offset + 5, $length);

    return Mu unless defined $decrypted;

    my $decompressed = Protocol::TLS::Compression::decode($ctx, $decrypted, 0, $decrypted.elems);

    return Mu unless defined %decoder{$type}.($ctx, $decompressed, 0, $decompressed.elems);

    return 5 + $offset;
  }

  method record-encode($ctx, $version, $type, *@s) {
    my $payload = Protocol::TLS::Protection::encode(
      $ctx, $version, $type, Protocol::TLS::Compression::encode(
        $ctx, %encoder{$type}.($ctx, |@s)
      )
    );
    pack('Cn2', $type, $version, $payload.elems) ~ $payload;
  }
}

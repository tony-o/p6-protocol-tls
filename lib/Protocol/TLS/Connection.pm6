use Protocol::TLS::Trace;

class Protocol::TLS::Connection {
  has $.tracer = Protocol::TLS::Trace.instance;
  has $.ctx;
  has $.input  = '';

  method next-record() {
    my $record = $.ctx.dequeue;
    $.tracer.debug(sprintf "send one record of %i bytes to wire\n", $record.bytes) if $record;
    $record;
  }
  method feed($chunk) {
    $.input ~= $chunk;
    my $offset = 0;
    my $len;
    $.tracer.debug("got {$chunk.bytes} bytes on wire\n");
    while $len = $.ctx.record-decode($.input, $offset) {
      $.tracer.debug("decoded record \@ $offset, length $len\n");
      $offset += $len;
    }
    $.input.substr(0, $offset) = '' if $offset;
  }
  method shutdown {
    $.ctx.shutdown;
  }
}

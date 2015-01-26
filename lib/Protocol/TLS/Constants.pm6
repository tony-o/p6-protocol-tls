constant TLS_v10 is export = 0x0301;
constant TLS_v11 is export = 0x0302;
constant TLS_v12 is export = 0x0303;
constant TLS_v13 is export = 0x0304;
                
# connectionEnd
constant CLIENT is export = 0;
constant SERVER is export = 1;
                             
# Content Type
constant CTYPE_CHANGE_CIPHER_SPEC is export = 20;
constant CTYPE_ALERT              is export = 21;
constant CTYPE_HANDSHAKE          is export = 22;
constant CTYPE_APPLICATION_DATA   is export = 23;
                                                  
# Handshake Type
constant HSTYPE_HELLO_REQUEST       is export = 0;
constant HSTYPE_CLIENT_HELLO        is export = 1;
constant HSTYPE_SERVER_HELLO        is export = 2;
constant HSTYPE_CERTIFICATE         is export = 11;
constant HSTYPE_SERVER_KEY_EXCHANGE is export = 12;
constant HSTYPE_CERTIFICATE_REQUEST is export = 13;
constant HSTYPE_SERVER_HELLO_DONE   is export = 14;
constant HSTYPE_CERTIFICATE_VERIFY  is export = 15;
constant HSTYPE_CLIENT_KEY_EXCHANGE is export = 16;
constant HSTYPE_FINISHED            is export = 20;
                                                                                               
# Ciphers
constant TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 is export = 0xc02b;
constant TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   is export = 0xc02f;
constant TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    is export = 0xc00a;
constant TLS_RSA_WITH_AES_128_CBC_SHA            is export = 0x002f;
constant TLS_RSA_WITH_3DES_EDE_CBC_SHA           is export = 0x000a;
constant TLS_RSA_WITH_RC4_128_SHA                is export = 0x0005;
constant TLS_RSA_WITH_RC4_128_MD5                is export = 0x0004;
constant TLS_RSA_WITH_NULL_SHA256                is export = 0x003b;
constant TLS_RSA_WITH_NULL_SHA                   is export = 0x0002;
constant TLS_NULL_WITH_NULL_NULL                 is export = 0x0000;
                                                                                                                                            
# State
constant STATE_IDLE        is export = 0;
constant STATE_HS_START    is export = 1;
constant STATE_SESS_NEW    is export = 2;
constant STATE_SESS_RESUME is export = 3;
constant STATE_HS_RESUME   is export = 4;
constant STATE_HS_HALF     is export = 5;
constant STATE_HS_FULL     is export = 6;
constant STATE_OPEN        is export = 7;
                                                                                                                                                                                 
# Alert
constant WARNING is export = 1;
constant FATAL   is export = 2;
                                                                                                                                                                                              
# Alert description
constant CLOSE_NOTIFY                is export = 0;
constant UNEXPECTED_MESSAGE          is export = 10;
constant BAD_RECORD_MAC              is export = 20;
constant DECRYPTION_FAILED_RESERVED  is export = 21;
constant RECORD_OVERFLOW             is export = 22;
constant DECOMPRESSION_FAILURE       is export = 30;
constant HANDSHAKE_FAILURE           is export = 40;
constant NO_CERTIFICATE_RESERVED     is export = 41;
constant BAD_CERTIFICATE             is export = 42;
constant UNSUPPORTED_CERTIFICATE     is export = 43;
constant CERTIFICATE_REVOKED         is export = 44;
constant CERTIFICATE_EXPIRED         is export = 45;
constant CERTIFICATE_UNKNOWN         is export = 46;
constant ILLEGAL_PARAMETER           is export = 47;
constant UNKNOWN_CA                  is export = 48;
constant ACCESS_DENIED               is export = 49;
constant DECODE_ERROR                is export = 50;
constant DECRYPT_ERROR               is export = 51;
constant EXPORT_RESTRICTION_RESERVED is export = 60;
constant PROTOCOL_VERSION            is export = 70;
constant INSUFFICIENT_SECURITY       is export = 71;
constant INTERNAL_ERROR              is export = 80;
constant USER_CANCELED               is export = 90;
constant NO_RENEGOTIATION            is export = 100;
constant UNSUPPORTED_EXTENSION       is export = 110;

my %tags = 
    versions => [qw<TLS_v10 TLS_v11 TLS_v12 TLS_v13>],
    c_types  => [
        qw< CTYPE_CHANGE_CIPHER_SPEC CTYPE_ALERT CTYPE_HANDSHAKE
          CTYPE_APPLICATION_DATA >
    ],
    hs_types => [
        qw< HSTYPE_HELLO_REQUEST HSTYPE_CLIENT_HELLO HSTYPE_SERVER_HELLO
          HSTYPE_CERTIFICATE HSTYPE_SERVER_KEY_EXCHANGE
          HSTYPE_CERTIFICATE_REQUEST HSTYPE_SERVER_HELLO_DONE
          HSTYPE_CERTIFICATE_VERIFY HSTYPE_CLIENT_KEY_EXCHANGE HSTYPE_FINISHED >
    ],
    end_types => [qw< CLIENT SERVER >],
    ciphers   => [
        qw< TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
          TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
          TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA TLS_RSA_WITH_AES_128_CBC_SHA
          TLS_RSA_WITH_3DES_EDE_CBC_SHA TLS_RSA_WITH_RC4_128_SHA
          TLS_RSA_WITH_RC4_128_MD5 TLS_RSA_WITH_NULL_SHA256 TLS_RSA_WITH_NULL_SHA
          TLS_NULL_WITH_NULL_NULL >
    ],
    state_types => [
        qw< STATE_IDLE STATE_HS_START STATE_SESS_NEW STATE_SESS_RESUME
          STATE_HS_RESUME STATE_HS_HALF STATE_HS_FULL STATE_OPEN >
    ],
    alert_types => [qw< WARNING FATAL >],
    alert_desc  => [
        qw< CLOSE_NOTIFY UNEXPECTED_MESSAGE BAD_RECORD_MAC
          DECRYPTION_FAILED_RESERVED RECORD_OVERFLOW DECOMPRESSION_FAILURE
          HANDSHAKE_FAILURE NO_CERTIFICATE_RESERVED BAD_CERTIFICATE
          UNSUPPORTED_CERTIFICATE CERTIFICATE_REVOKED CERTIFICATE_EXPIRED
          CERTIFICATE_UNKNOWN ILLEGAL_PARAMETER UNKNOWN_CA ACCESS_DENIED
          DECODE_ERROR DECRYPT_ERROR EXPORT_RESTRICTION_RESERVED PROTOCOL_VERSION
          INSUFFICIENT_SECURITY INTERNAL_ERROR USER_CANCELED NO_RENEGOTIATION
          UNSUPPORTED_EXTENSION>
    ],
;

my (%reverse, %ciphers);
for %tags.keys -> $k {
  for %tags{$k}.values -> $v {
    %reverse{$k}{EVAL ($v)} = $v;
  }
}

for %reverse<ciphers>.keys -> $c {
  %ciphers{$c} = [
    %reverse<ciphers>{$c}.Str ~~ / ^ 'TLS_' (.+) '_WITH_' (.+) '_' ([^_]+) $/
  ];
}

class Protocol::TLS::Constants {
  method new {!!!};  
  method const_name($tag, $value) {
    %reverse{$tag} // False ?? %reverse{$tag}{$value} // '' !! ''; 
  }
  method is_tls_version($vers) {
    $vers < TLS_v10 || $vers > TLS_v12 ?? Nil !! $vers;
  }
  method cipher_type($c) {
    %ciphers{$c} // Array.new;
  }
}

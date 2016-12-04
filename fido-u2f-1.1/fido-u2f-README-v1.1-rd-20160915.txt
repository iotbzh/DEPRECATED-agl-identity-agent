===============================================================================
             GUIDE TO DOCS: FIDO U2F Spec Package September 15, 2016
===============================================================================

The following documents make up the FIDO U2F Spec package. These specs are
implemented in the reference implementation available as open source at
https://github.com/google/u2f-ref-code/

If you are reading this guide as a first page of a PDF file, all the
documents listed below are part of the same PDF file. This PDF file
was created from the documents checked into the document management
system (gihtub) being used for this purpose.

If you are reading this document on the github source control system,
the documents listed below are in the same directory as this document
that you are reading.

  =-=-=-=
  FIDO U2F Architectural Overview
  fido-u2f-overview-v1.1-rd-20160915.html

  This overview document describes the various design considerations
  which go into the protocol in detail and describes the user flows in
  detail. It describes the layering and intention of each of the
  detailed protocol documents. It describes the various privacy
  considerations in the protocol design through the document and
  summarizes these at the end.

  It is recommended that you read this document first if you are new
  to U2F.

  =-=-=-=
  FIDO U2F Javascript API
  fido-u2f-javascript-api-v1.1-rd-20160915.html

  This document describes the client side API in the web browser for
  accessing U2F capabilities. An online service or website can
  leverage U2F by using this API on the client side and pairing it
  with a server which can verify U2F messages on the server
  side. (Later specifications will be developed for APIs in
  non-browser contexts).

  =-=-=-=
  FIDO U2F Raw Message Formats
  fido-u2f-raw-message-formats-v1.1-rd-20160915.html

  This document describes the binary format of request messages which
  go from the FIDO U2F server to the FIDO U2F token and the binary
  format of the response messages from the token to the server. These
  messages are encoded by the browser (FIDO client) for communication
  to the token over a particular transport (such as USB) to the
  cryptographic core of the token which performs key generation and
  signing.

  =-=-=-=
  FIDO U2F HID Protocol Specification
  fido-u2f-hid-protocol-v1.1-rd-20160915.html

  This document describes how messages sent from the FIDO Client to
  the USB U2F token are framed over USB HID. Only the framing is
  described, the actual U2F messages sent are described in FIDO U2F
  Raw Message Formats document (above).

  =-=-=-=
  FIDO U2F Implementation Considerations
  fido-u2f-implementation-considerations-v1.1-rd-20160915.html

  This document describes implementation considerations and
  recommendations for creators of U2F devices and for relying parties
  implementing U2F support.

  =-=-=-=
  FIDO AppID and Facet Specification
  fido-appid-and-facets-v1.1-rd-20160915.html

  The U2F protocol ensures that the origin foo.com can only exercise a
  key that was issued for foo.com by the U2F token.  foo.com may have
  an app in non-browser environments and the same portable token may
  be exercised there too. This document describes how the various
  embodiments of foo.com (in a browser, in a mobile OS etc) securely
  assert the same origin to the token. This document applies to both
  the U2F and the UAF protocol.

  =-=-=-=
  FIDO Common Header Files
  u2f.h
  u2f_hid.h

  These header files define the values of symbolic constants and data
  structures referred to in the FIDO U2F Raw Messages document and the
  FIDO U2F HID Protocol Specification documents.

  =-=-=-=
  FIDO Bluetooth Specification
  fido-u2f-bt-protocol-v1.1-rd-20160915.html

  This document describes how the U2F protocol should be performed between a
  FIDO client and a Bluetooth Low Energy FIDO authenticator.

  =-=-=-=
  FIDO NFC Specification
  fido-u2f-nfc-protocol-v1.1-rd-20160915.html

  This document describes how the U2F protocol should be performed between a
  FIDO client and an NFC FIDO authenticator.

  =-=-=-=

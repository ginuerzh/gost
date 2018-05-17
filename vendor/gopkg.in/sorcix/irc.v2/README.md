# Go **irc** package

[![Build Status](https://travis-ci.org/sorcix/irc.svg?branch=v2)](https://travis-ci.org/sorcix/irc)
[![GoDoc](https://godoc.org/gopkg.in/sorcix/irc.v2?status.svg)](https://godoc.org/gopkg.in/sorcix/irc.v2)

## Features
Package irc allows your application to speak the IRC protocol.

 - **Limited scope**, does one thing and does it well.
 - Focus on simplicity and **speed**.
 - **Stable API**: updates shouldn't break existing software.
 - Well [documented][Documentation] code.

*This package does not manage your entire IRC connection. It only translates the protocol to easy to use Go types. It is meant as a single component in a larger IRC library, or for basic IRC bots for which a large IRC package would be overkill.*

## Usage

```
import "gopkg.in/sorcix/irc.v2"
```

### Message
The [Message][] and [Prefix][] types provide translation to and from IRC message format.

    // Parse the IRC-encoded data and stores the result in a new struct.
    message := irc.ParseMessage(raw)

    // Returns the IRC encoding of the message.
    raw = message.String()

### Encoder & Decoder
The [Encoder][] and [Decoder][] types allow working with IRC message streams.

    // Create a decoder that reads from given io.Reader
    dec := irc.NewDecoder(reader)

    // Decode the next IRC message
    message, err := dec.Decode()

    // Create an encoder that writes to given io.Writer
    enc := irc.NewEncoder(writer)

    // Send a message to the writer.
    enc.Encode(message)

### Conn
The [Conn][] type combines an [Encoder][] and [Decoder][] for a duplex connection.

    c, err := irc.Dial("irc.server.net:6667")

    // Methods from both Encoder and Decoder are available
    message, err := c.Decode()

[Documentation]: https://godoc.org/gopkg.in/sorcix/irc.v2 "Package documentation by Godoc.org"
[Message]: https://godoc.org/gopkg.in/sorcix/irc.v2#Message "Message type documentation"
[Prefix]: https://godoc.org/gopkg.in/sorcix/irc.v2#Prefix "Prefix type documentation"
[Encoder]: https://godoc.org/gopkg.in/sorcix/irc.v2#Encoder "Encoder type documentation"
[Decoder]: https://godoc.org/gopkg.in/sorcix/irc.v2#Decoder "Decoder type documentation"
[Conn]: https://godoc.org/gopkg.in/sorcix/irc.v2#Conn "Conn type documentation"
[RFC1459]: https://tools.ietf.org/html/rfc1459.html "RFC 1459"

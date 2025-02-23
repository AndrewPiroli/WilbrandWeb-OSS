## Wilbrand web service implementation (Open Source Edition)

This is the Wilbrand Wii System Menu exploit implementation running on
https://wilbrand.andrewtech.net/. Requires Python 3.7+, Flask, and Flask-Limiter.

This does not include the HackMii Installer bundle. Those files would go
in `bundle/`.

#### Differences

 This repo is shamelessly built off my Letterbomb fork that is running at https://letterbomb.andrewtech.net and
 so inherits that projects general ideas:

  * No captcha (Rate limiting in place of course)
  * No Geo-IP
  * Cool counter
  * Reverse proxy aware


### License

GPL-2.0 due to the inherited history of Letterbomb

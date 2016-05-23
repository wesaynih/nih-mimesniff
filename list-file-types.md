# List of standard supported file types

* image - An image type is any parsable MIME type where type is equal to `image`.
* audio or video - An audio or video type is any parsable MIME type where type is equal to `audio` or `video` or where the `MIME type` portion is equal to one of the following:
  * `application/ogg`
* font - A font type is any `parsable MIME type` where the `MIME type` portion is equal to one of the following:
  * `application/font-ttf`
  * `application/font-cff`
  * `application/font-off`
  * `application/font-sfnt`
  * `application/vnd.ms-opentype`
  * `application/font-woff`
  * `application/vnd.ms-fontobject`
* zip - A `ZIP-based type` is any `parsable MIME type` where the `subtype` ends in `+zip` or the `MIME type portion` is equal to one of the following: 
  * `application/zip`
* archive - An `archive type` is any `parsable MIME type` where the `MIME type portion` is equal to one of the following:
  * `application/x-rar-compressed`
  * `application/zip`
  * `application/x-gzip`
* xml - An `XML type` is any `parsable MIME type` where the `subtype` ends in `+xml` or the `MIME type portion` is equal to the following: 
  * `text/xml`
  * `application/xml`
* scriptable - A `scriptable MIME type` is an `XML type` or any `parsable MIME type` where the `MIME type portion` is equal to one of the following:
  * `text/html`
  * `application/pdf`

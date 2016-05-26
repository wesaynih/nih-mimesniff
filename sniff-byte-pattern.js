'use strict';

var sniff = (function ()
{
    var bytePatterns = {
        'image/x-icon': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [[0, 0x00, 0x01, 0x00], [0x00, 0x00, 0x02, 0x00]]
        },
        'image/bmp': {
            'byteNr':   [0, 1],
            'patterns': [0x42,  0x4D],
            'regexp':   /^BM/
        },
        'image/gif': {
            'byteNr':   [0, 1, 2, 3, 4, 5],
            'patterns': [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]],
            'regexp':   /^(GIF87a|GIF89a)/
        },
        'image/webp': {
            'byteNr':   [0, 1, 2, 3, 8, 9, 10, 11, 12, 13],
            'patterns': [0x52, 0x49, 0x46, 0x46, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50],
            'regexp':   /^RIFF....WEBPVP/
        },
        'image/png': {
            'byteNr':   [0, 1, 2, 3, 4, 5, 6, 7],
            'patterns': [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            'regexp':   /^\u0089PNG\u000D\u000A\u001A\u000A/
        },
        'image/jpeg': {
            'byteNr':   [0, 1, 2],
            'patterns': [0xFF, 0xD8, 0xFF]
        },
        'audio/basic': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x2E, 0x73, 0x6E, 0x64],
            'regexp':   /^.snd/
        },
        'audio/aiff': {
            'byteNr':   [0, 1, 2, 3, 8, 9, 10, 11],
            'patterns': [0x46, 0x4F, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x41, 0x49, 0x46, 0x46],
            'regexp':   /^FORM....AIFF/
        },
        'audio/mpeg': {
            'byteNr':   [0, 1, 2],
            'patterns': [0x49, 0x44, 0x33],
            'regexp':   /^ID3/
        },
        'application/ogg': {
            'byteNr':   [0, 1, 2, 3, 4],
            'patterns': [0x4F, 0x67, 0x67, 0x53, 0x00],
            'regexp':   /^OggS\0/
        },
        'audio/midi': {
            'byteNr':   [0, 1, 2, 3, 4, 5, 6, 7],
            'patterns': [0x4D, 0x54, 0x68, 0x64, 0x00, 0x00, 0x00, 0x06],
            'regexp':   /^MThd\0\0\0\u0006/
        },
        'video/avi': {
            'byteNr':   [0, 1, 2, 3, 8, 9, 10, 11],
            'patterns': [0x52, 0x49, 0x46, 0x46, 0x41, 0x56, 0x49, 0x20],
            'regexp':   /^RIFF....AVI/
        },
        'audio/wave': {
            'byteNr':   [0, 1, 2, 3, 8, 9, 10, 11],
            'patterns': [0x52, 0x49, 0x46, 0x46, 0x57, 0x41, 0x56, 0x45],
            'regexp':   /^RIFF....WAVE/
        },
        'application/vnd.ms-fontobject': {
            'byteNr':   [35, 36],
            'patterns': [0x4C, 0x50],
            'regexp':   /^.{34}LP/
        },
        'application/x-unknown-content-type; name="TrueType"': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x00, 0x01, 0x00, 0x00]
        },
        'application/x-unknown-content-type; name="OpenType"': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x4F, 0x54, 0x54, 0x4F],
            'regexp':   /^OTTO/
        },
        'application/x-unknown-content-type; name="TrueType Collection"': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x74, 0x74, 0x63, 0x66],
            'regexp':   /^ttcf/
        },
        'application/font-woff': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x77, 0x4F, 0x46, 0x46],
            'regexp':   /^wOFF/
        },
        'application/x-gzip': {
            'byteNr':   [0, 1, 2],
            'patterns': [0x1F, 0x8B, 0x08]
        },
        'application/zip': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x50, 0x4B, 0x03, 0x04],
            'regexp':   /^PK\u0003\u0004/
        },
        'application/x-rar-compressed': {
            'byteNr':   [0, 1, 2, 3, 4, 5, 6],
            'patterns': [0x52, 0x61, 0x72, 0x20, 0x1A, 0x07, 0x00],
            'regexp':   /^Rar \u001A\u0007\0/
        },
        'text/html': {
            'regexp':
            [
                /^<(!(DOCTYPE HTML|--)|HTML|HEAD|SCRIPT|IFRAME|H1|DIV|FONT|TABLE|A|STYLE|TITLE|B|BODY|BR|P)[ >]/i,
                /^<!DOCTYPE HTML[ >]/i,
                /^<HTML[ >]/i,
                /^<HEAD[ >]/i,
                /^<SCRIPT[ >]/i,
                /^<IFRAME[ >]/i,
                /^<H1[ >]/i,
                /^<DIV[ >]/i,
                /^<FONT[ >]/i,
                /^<TABLE[ >]/i,
                /^<A[ >]/i,
                /^<STYLE[ >]/i,
                /^<TITLE[ >]/i,
                /^<B[ >]/i,
                /^<BODY[ >]/i,
                /^<BR[ >]/i,
                /^<P[ >]/i,
                /^<!--[ >]/
            ]
        },
        'text/xml': {
            'byteNr':   [0, 1, 2, 3, 4],
            'patterns': [0x3C, 0x3F, 0x78, 0x6D, 0x6C],
            'regexp':   /^<[?]xml]/
        },
        'application/pdf': {
            'byteNr':   [0, 1, 2, 3, 4],
            'patterns': [0x25, 0x50, 0x44, 0x46, 0x2D],
            'regexp':   /^%PDF-/
        },
        'application/postscript': {
            'byteNr':   [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            'patterns': [0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D],
            'regexp':   /^%!PS-Adobe-/
        },
        'text/plain': {
            'byteNr':   [0, 1],
            'patterns': [[0xFF, 0xFE], [0xFE, 0xFF]]
        },
        'text/plain option2': {
            'byteNr':   [0, 1, 2],
            'patterns': [0xEF, 0xBB, 0xBF]
        }
    };

    /**
    * @param {Uint8Array} bytes
    * @return {string}
    */
    function sniffy(bytes)
    {
        var current, input, mimeType, i, pattern,
            match = false,
            notImplemented = [];

        /**
        * @param {number} nr
        * @return {Uint8}
        */
        function inputByteAt(nr)
        {
            return bytes[nr];
        }

        /**
        * @param {Uint8Array | Array<number>} inp, ptrn
        * @return {boolean}
        */
        function isMime(inp, ptrn)
        {
            var j;

            if (inp.length === ptrn.length)
            {
                for (j = 0; j < ptrn.length; j++)
                {
                    // If true check if first value of inp and ptrn match
                    if (inp[j] !== ptrn[j])
                    {
                        return false;
                    }
                    else if (inp[j] === ptrn[j] && j === ptrn.length - 1)
                    {
                        return true;
                    }
                }
            }
            else if (ptrn instanceof RegExp)
            {
                // TODO: implement matching with regexp patterns
                console.log('Regexp matching is currently not implemented!');
            }

            return false;
        }

        // For each mime type
        for (mimeType in bytePatterns)
        {
            if (bytePatterns.hasOwnProperty(mimeType))
            {
                current = bytePatterns[mimeType];

                // Create array of relevant bytes for mimesniff input
                if (current.byteNr)
                {
                    input = current.byteNr.map(inputByteAt);
                }
                else
                {
                    notImplemented.push(mimeType);
                    input = [];
                }

                if (current.patterns && typeof current.patterns[0] == 'number')
                {
                    pattern = current.patterns;
                }
                else if (current.patterns && current.patterns.length > 1)
                {
                    // TODO: implement for multiple patterns
                    pattern = current.patterns[0];
                }
                else
                {
                    notImplemented.push(mimeType);
                }

                if (isMime(input, pattern))
                {
                    match = true;
                    break;
                }
            }
        }

        if (!match)
        {
            mimeType = 'application/octet-stream';
        }

        //  console.log('TODO: implement: ' + notImplemented.join(', '));
        return mimeType;
    }

    return sniffy;
}());

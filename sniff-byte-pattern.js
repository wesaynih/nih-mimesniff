'use strict';

var sniff = (function ()
{
    var bytePatterns = {
        'image/x-icon': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [[0x00, 0x00, 0x01, 0x00], [0x00, 0x00, 0x02, 0x00]]
        },
        'image/bmp': {
            'byteNr':   [0, 1],
            'patterns': [0x42,  0x4D],
            'regexp':   [/^BM/]
        },
        'image/gif': {
            'byteNr':   [0, 1, 2, 3, 4, 5],
            'patterns': [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]],
            'regexp':   [/^(GIF87a|GIF89a)/]
        },
        'image/webp': {
            'byteNr':   [0, 1, 2, 3, 8, 9, 10, 11, 12, 13],
            'patterns': [0x52, 0x49, 0x46, 0x46, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50],
            'regexp':   [/^RIFF....WEBPVP/]
        },
        'image/png': {
            'byteNr':   [0, 1, 2, 3, 4, 5, 6, 7],
            'patterns': [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            'regexp':   [/^\u0089PNG\u000D\u000A\u001A\u000A/]
        },
        'image/jpeg': {
            'byteNr':   [0, 1, 2],
            'patterns': [0xFF, 0xD8, 0xFF]
        },
        'audio/basic': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x2E, 0x73, 0x6E, 0x64],
            'regexp':   [/^.snd/]
        },
        'audio/aiff': {
            'byteNr':   [0, 1, 2, 3, 8, 9, 10, 11],
            'patterns': [0x46, 0x4F, 0x52, 0x4D, 0x41, 0x49, 0x46, 0x46],
            'regexp':   [/^FORM....AIFF/]
        },
        'audio/mpeg': {
            'byteNr':   [0, 1, 2],
            'patterns': [0x49, 0x44, 0x33],
            'regexp':   [/^ID3/]
        },
        'application/ogg': {
            'byteNr':   [0, 1, 2, 3, 4],
            'patterns': [0x4F, 0x67, 0x67, 0x53, 0x00],
            'regexp':   [/^OggS\0/]
        },
        'audio/midi': {
            'byteNr':   [0, 1, 2, 3, 4, 5, 6, 7],
            'patterns': [0x4D, 0x54, 0x68, 0x64, 0x00, 0x00, 0x00, 0x06],
            'regexp':   [/^MThd\0\0\0\u0006/]
        },
        'video/avi': {
            'byteNr':   [0, 1, 2, 3, 8, 9, 10, 11],
            'patterns': [0x52, 0x49, 0x46, 0x46, 0x41, 0x56, 0x49, 0x20],
            'regexp':   [/^RIFF....AVI/]
        },
        'audio/wave': {
            'byteNr':   [0, 1, 2, 3, 8, 9, 10, 11],
            'patterns': [0x52, 0x49, 0x46, 0x46, 0x57, 0x41, 0x56, 0x45],
            'regexp':   [/^RIFF....WAVE/]
        },
        'application/vnd.ms-fontobject': {
            'byteNr':   [35, 36],
            'patterns': [0x4C, 0x50],
            'regexp':   [/^.{34}LP/]
        },
        'application/x-unknown-content-type; name="TrueType"': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x00, 0x01, 0x00, 0x00]
        },
        'application/x-unknown-content-type; name="OpenType"': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x4F, 0x54, 0x54, 0x4F],
            'regexp':   [/^OTTO/]
        },
        'application/x-unknown-content-type; name="TrueType Collection"': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x74, 0x74, 0x63, 0x66],
            'regexp':   [/^ttcf/]
        },
        'application/font-woff': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x77, 0x4F, 0x46, 0x46],
            'regexp':   [/^wOFF/]
        },
        'application/x-gzip': {
            'byteNr':   [0, 1, 2],
            'patterns': [0x1F, 0x8B, 0x08]
        },
        'application/zip': {
            'byteNr':   [0, 1, 2, 3],
            'patterns': [0x50, 0x4B, 0x03, 0x04],
            'regexp':   [/^PK\u0003\u0004/]
        },
        'application/x-rar-compressed': {
            'byteNr':   [0, 1, 2, 3, 4, 5, 6],
            'patterns': [0x52, 0x61, 0x72, 0x20, 0x1A, 0x07, 0x00],
            'regexp':   [/^Rar \u001A\u0007\0/]
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
            'regexp':   [/^<[?]xml]/]
        },
        'application/pdf': {
            'byteNr':   [0, 1, 2, 3, 4],
            'patterns': [0x25, 0x50, 0x44, 0x46, 0x2D],
            'regexp':   [/^%PDF-/]
        },
        'application/postscript': {
            'byteNr':   [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            'patterns': [0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65, 0x2D],
            'regexp':   [/^%!PS-Adobe-/]
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
        var i, ii, fbType, mime,
            match = false,
            fallback = ['text/plain', 'text/plain option2'],

            // Set mimeType to application/octet-stream as a last resort
            mimeType = 'application/octet-stream',
            notImplemented = [];

        // TODO: Use only the first 1024 bytes or so from `bytes`, to prevent creating huge strings

        /**
        * @param {number} nr
        * @return {Uint8}
        */
        function inputByteAt(nr)
        {
            return bytes[nr];
        }

        /**
        * @param {string | regexp} inp, ptrn
        * @return {boolean}
        */
        function testRegexp(inp, ptrn)
        {
            return ptrn.test(inp);
        }

        /**
        * @param {Uint8Array | Array<number>} inp, ptrn
        * @return {boolean}
        */
        function testPattern(values)
        {
            var j, jj, pattern,
                input = values[0],
                patterns = values[1];

            for (j = 0; j < patterns.length; j++)
            {
                pattern = patterns[j];

                // Check for regexp or non-matching patternBytes/inputBytes
                if (pattern instanceof RegExp)
                {
                    return testRegexp(input, pattern);
                }
                else if (input.length !== pattern.length)
                {
                    return false;
                }

                // Check each inputByte against patternByte
                for (jj = 0; jj < pattern.length; jj++)
                {
                    if (input[jj] !== pattern[jj])
                    {
                        return false;
                    }
                    else if (input[jj] === pattern[jj] && jj === pattern.length - 1)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /**
        * @param {string} testType
        * @return {Array} [input,pattern]
        */
        function setTestValues(testType)
        {
            var input, patterns,
                inputString = String.fromCharCode.apply(null, bytes);

            // If regexp pattern exists, test against input string
            if (testType.regexp)
            {
                patterns = testType.regexp;
                input = inputString;
            }

            // If no regexp pattern, check if a single pattern exists
            else if (testType.patterns)
            {
                patterns = testType.patterns;

                // Create array around single pattern values
                if (typeof patterns[0] == 'number')
                {
                    patterns = [patterns];
                }

                // Check if bytenumber mapping exists
                if (testType.byteNr)
                {
                    input = testType.byteNr.map(inputByteAt);
                }
                else
                {
                    // log mimeType if no bytenumber mapping exists
                    notImplemented.push(mimeType);
                    throw new Error('No byte map provided for ' + mimeType);
                }
            }
            else
            {
                notImplemented.push(mimeType);
            }

            return [input, patterns];
        }

        /**
        * @param {String} mime
        * @return {Boolean}
        */
        function isMime(thisMime)
        {
            // Set testvalues based on current mimeType
            var testValues = setTestValues(thisMime);

            // Test if current mimeType matches
            return testPattern(testValues);
        }

        // For each mime type
        for (mimeType in bytePatterns)
        {
            if (bytePatterns.hasOwnProperty(mimeType))
            {
                mime = bytePatterns[mimeType];

                // Exclude fallback mimeTypes from this first set of tests
                if (fallback.indexOf(mimeType) === -1)
                {
                    match = isMime(mime);
                    if (match)
                    {
                        mimeType = mimeType;
                        break;
                    }
                }

                // Test if one of the fallback mimeTypes matches
                if (!match)
                {
                    for (i = 0; i < fallback.length; i++)
                    {
                        fbType = bytePatterns[fallback[i]];
                        match = isMime(fbType);
                        if (match)
                        {
                            mimeType = fbType;
                        }
                    }
                }
            }
        }

        //  console.log('TODO: implement: ' + notImplemented.join(', '));
        return mimeType;
    }

    return sniffy;
}());

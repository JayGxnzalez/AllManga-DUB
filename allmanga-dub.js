// AllManga (DUB) Module
// Pure JS AES-256-GCM decryption + clock.json resolution
// Uses persisted query hashes + AES-256-GCM decryption + clock.json resolution

var ALLANIME_API = 'https://api.allanime.day/api';
var ALLANIME_REFR = 'https://allmanga.to';
var ALLANIME_KEY = 'a254aa27c410f297bd04ba33a0c0df7ff4e706bf3ae27271c6703f84e750f552';

var SEARCH_HASH = 'a24c500a1b765c68ae1d8dd85174931f661c71369c89b92b88b75a725afc471c';
var EPISODES_HASH = '043448386c7a686bc2aabfbb6b80f6074e795d350df48015023b079527b0848a';
var SOURCES_HASH = 'd405d0edd690624b66baba3068e0edc3ac90f1597d898a1ec8db4e5c43c00fec';

var HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Origin': ALLANIME_REFR,
    'Referer': ALLANIME_REFR + '/'
};

var SOURCES_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Origin': 'https://youtu-chan.com',
    'Referer': 'https://youtu-chan.com'
};

var HEX_MAP = {
    '79':'A','7a':'B','7b':'C','7c':'D','7d':'E','7e':'F','7f':'G','70':'H','71':'I','72':'J',
    '73':'K','74':'L','75':'M','76':'N','77':'O','68':'P','69':'Q','6a':'R','6b':'S','6c':'T',
    '6d':'U','6e':'V','6f':'W','60':'X','61':'Y','62':'Z','59':'a','5a':'b','5b':'c','5c':'d',
    '5d':'e','5e':'f','5f':'g','50':'h','51':'i','52':'j','53':'k','54':'l','55':'m','56':'n',
    '57':'o','48':'p','49':'q','4a':'r','4b':'s','4c':'t','4d':'u','4e':'v','4f':'w','40':'x',
    '41':'y','42':'z','08':'0','09':'1','0a':'2','0b':'3','0c':'4','0d':'5','0e':'6','0f':'7',
    '00':'8','01':'9','15':'-','16':'.','67':'_','46':'~','02':':','17':'/','07':'?','1b':'#',
    '63':'[','65':']','78':'@','19':'!','1c':'$','1e':'&','10':'(','11':')','12':'*','13':'+',
    '14':',','03':';','05':'=','1d':'%'
};

var SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
];

function hexToBytes(hex) {
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function base64ToBytes(b64) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var str = String(b64).replace(/=+$/, '');
    var output = new Uint8Array(Math.floor(str.length * 3 / 4) + 3);
    var bc = 0, bs = 0, idx = 0;
    for (var i = 0; i < str.length; i++) {
        var buffer = chars.indexOf(str.charAt(i));
        if (~buffer) {
            bs = bc % 4 ? bs * 64 + buffer : buffer;
            if (bc++ % 4) output[idx++] = 255 & bs >> (-2 * bc & 6);
        }
    }
    return output.slice(0, idx);
}

function xtime(a) { return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff; }

function aesSubBytes(state) {
    for (var i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

function aesShiftRows(state) {
    var t;
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t;
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t;
}

function aesMixColumns(state) {
    for (var i = 0; i < 16; i += 4) {
        var s0 = state[i], s1 = state[i+1], s2 = state[i+2], s3 = state[i+3];
        var h = s0 ^ s1 ^ s2 ^ s3;
        state[i]   ^= h ^ xtime(s0 ^ s1);
        state[i+1] ^= h ^ xtime(s1 ^ s2);
        state[i+2] ^= h ^ xtime(s2 ^ s3);
        state[i+3] ^= h ^ xtime(s3 ^ s0);
    }
}

function aesAddRoundKey(state, w, round) {
    for (var i = 0; i < 16; i++) state[i] ^= w[round * 16 + i];
}

function aesKeyExpansion(key) {
    var RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
    var w = new Uint8Array(240);
    w.set(key);
    for (var i = 8; i < 60; i++) {
        var t = w.slice((i-1)*4, i*4);
        if (i % 8 === 0) {
            t = new Uint8Array([SBOX[t[1]]^RCON[i/8-1], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]);
        } else if (i % 8 === 4) {
            t = new Uint8Array([SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]]);
        }
        for (var j = 0; j < 4; j++) w[i*4+j] = w[(i-8)*4+j] ^ t[j];
    }
    return w;
}

function aesEncryptBlock(block, w) {
    var state = new Uint8Array(block);
    aesAddRoundKey(state, w, 0);
    for (var round = 1; round < 14; round++) {
        aesSubBytes(state);
        aesShiftRows(state);
        aesMixColumns(state);
        aesAddRoundKey(state, w, round);
    }
    aesSubBytes(state);
    aesShiftRows(state);
    aesAddRoundKey(state, w, 14);
    return state;
}

// GCM uses CTR mode starting at counter=2 for data (counter=1 is used for auth tag)
function aesGcmDecrypt(ciphertextWithTag, keyHex, iv) {
    var key = hexToBytes(keyHex);
    var w = aesKeyExpansion(key);

    // Separate ciphertext and auth tag (last 16 bytes)
    var ctLen = ciphertextWithTag.length - 16;
    var ciphertext = ciphertextWithTag.slice(0, ctLen);

    // Build initial counter block J0 from 12-byte IV: IV || 00000001
    var j0 = new Uint8Array(16);
    for (var i = 0; i < 12; i++) j0[i] = iv[i];
    j0[15] = 1;

    // Decrypt using CTR starting at counter=2
    var plaintext = new Uint8Array(ciphertext.length);
    for (var pos = 0; pos < ciphertext.length; pos += 16) {
        // Increment counter (big-endian increment of last 4 bytes)
        var ctr = new Uint8Array(j0);
        var blockNum = Math.floor(pos / 16) + 2;
        ctr[12] = (blockNum >>> 24) & 0xff;
        ctr[13] = (blockNum >>> 16) & 0xff;
        ctr[14] = (blockNum >>> 8) & 0xff;
        ctr[15] = blockNum & 0xff;
        var keystream = aesEncryptBlock(ctr, w);
        var blockSize = Math.min(16, ciphertext.length - pos);
        for (var k = 0; k < blockSize; k++) {
            plaintext[pos + k] = ciphertext[pos + k] ^ keystream[k];
        }
    }
    return plaintext;
}

function decodeTobeparsed(tobeparsed) {
    try {
        var b64 = tobeparsed;
        var pad = b64.length % 4;
        if (pad) b64 += '===='.slice(pad);
        var data = base64ToBytes(b64);
        // byte 0: skip, bytes 1-12: IV, bytes 13+: ciphertext+tag
        var iv = data.slice(1, 13);
        var ciphertextWithTag = data.slice(13);
        var plaintext = aesGcmDecrypt(ciphertextWithTag, ALLANIME_KEY, iv);
        var result = '';
        for (var i = 0; i < plaintext.length; i++) {
            result += String.fromCharCode(plaintext[i]);
        }
        try {
            return decodeURIComponent(escape(result));
        } catch(e) {
            return result;
        }
    } catch(e) {
        console.log('decodeTobeparsed error: ' + e);
        return null;
    }
}


function decodeProviderUrl(encoded) {
    if (encoded.indexOf('--') !== 0) return encoded;
    var hex = encoded.slice(2);
    var result = '';
    for (var i = 0; i < hex.length; i += 2) {
        var byte = hex.substr(i, 2);
        result += HEX_MAP[byte] || '';
    }
    return result.replace('/clock', '/clock.json');
}

async function soraFetch(url, options) {
    options = options || { headers: {}, method: 'GET', body: null };
    try {
        if (typeof fetchv2 !== 'undefined') {
            return await fetchv2(url, options.headers || {}, options.method || 'GET', options.body || null, true, options.encoding || 'utf-8');
        } else {
            return await fetch(url, options);
        }
    } catch(e) {
        try { return await fetch(url, options); } catch(err) { return null; }
    }
}

async function allanimeGet(variables, hash, customHeaders) {
    var encoded = encodeURIComponent(JSON.stringify(variables));
    var ext = encodeURIComponent(JSON.stringify({ persistedQuery: { version: 1, sha256Hash: hash } }));
    var url = ALLANIME_API + '?variables=' + encoded + '&extensions=' + ext;
    var headers = customHeaders || HEADERS;
    try {
        var res = await soraFetch(url, { headers: headers, method: 'GET', body: null });
        if (!res) return null;
        var text = typeof res.text === 'function' ? await res.text() : null;
        if (!text || text.trim().indexOf('<') === 0) return null;
        return JSON.parse(text);
    } catch(e) {
        console.log('AllManga API error: ' + e);
        return null;
    }
}

async function resolveStreamUrl(rawUrl) {
    try {
        var decoded = decodeProviderUrl(rawUrl);
        if (!decoded || decoded.indexOf('http') !== 0) return null;
        if (decoded.indexOf('clock.json') !== -1) {
            var res = await soraFetch(decoded, { method: 'GET', headers: HEADERS });
            if (!res) return null;
            var text = typeof res.text === 'function' ? await res.text() : null;
            if (!text) return null;
            var json = JSON.parse(text);
            if (json && json.links && json.links.length > 0) {
                return json.links[0].link || null;
            }
            return null;
        }
        return decoded;
    } catch(e) {
        console.log('resolveStreamUrl error: ' + e);
        return null;
    }
}

async function searchResults(keyword) {
    try {
        var variables = {
            search: { query: keyword },
            limit: 26,
            page: 1,
            translationType: 'dub',
            countryOrigin: 'ALL'
        };
        var data = await allanimeGet(variables, SEARCH_HASH);
        if (!data || !data.data || !data.data.shows || !data.data.shows.edges) return JSON.stringify([]);
        var results = [];
        var edges = data.data.shows.edges;
        for (var i = 0; i < edges.length; i++) {
            var show = edges[i];
            if (!show.availableEpisodes || !show.availableEpisodes.dub || show.availableEpisodes.dub === 0) continue;
            results.push({
                title: show.englishName || show.name || 'Unknown',
                image: show.thumbnail || '',
                href: show._id
            });
        }
        return JSON.stringify(results);
    } catch(e) {
        console.log('searchResults error: ' + e);
        return JSON.stringify([]);
    }
}

async function extractDetails(showId) {
    try {
        var variables = { _id: showId };
        var data = await allanimeGet(variables, EPISODES_HASH);
        if (!data || !data.data || !data.data.show) {
            return JSON.stringify([{ description: 'No description available', aliases: 'N/A', airdate: 'N/A' }]);
        }
        var show = data.data.show;
        var description = show.description
            ? show.description.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#039;/g, "'").replace(/&#xE9;/g, 'é').trim()
            : 'No description available';
        var year = show.airedStart && show.airedStart.year ? String(show.airedStart.year) : 'N/A';
        var score = show.averageScore ? show.averageScore + '/100' : 'N/A';
        return JSON.stringify([{
            description: description,
            aliases: 'Score: ' + score,
            airdate: 'Year: ' + year
        }]);
    } catch(e) {
        console.log('extractDetails error: ' + e);
        return JSON.stringify([{ description: 'No description available', aliases: 'N/A', airdate: 'N/A' }]);
    }
}

async function extractEpisodes(showId) {
    try {
        var variables = { _id: showId };
        var data = await allanimeGet(variables, EPISODES_HASH);
        if (!data || !data.data || !data.data.show) return JSON.stringify([]);
        var dubEpisodes = (data.data.show.availableEpisodesDetail && data.data.show.availableEpisodesDetail.dub) || [];
        if (!dubEpisodes.length) return JSON.stringify([]);
        var parsed = [];
        for (var i = 0; i < dubEpisodes.length; i++) {
            var n = parseFloat(dubEpisodes[i]);
            if (!isNaN(n)) parsed.push(n);
        }
        parsed.sort(function(a, b) { return a - b; });
        var results = [];
        for (var j = 0; j < parsed.length; j++) {
            results.push({ href: showId + '|' + parsed[j], number: parsed[j] });
        }
        return JSON.stringify(results);
    } catch(e) {
        console.log('extractEpisodes error: ' + e);
        return JSON.stringify([]);
    }
}

async function extractStreamUrl(slug) {
    try {
        var parts = slug.split('|');
        var showId = parts[0];
        var epNumber = parts[1];
        var variables = {
            showId: showId,
            translationType: 'dub',
            episodeString: String(epNumber)
        };
        var data = await allanimeGet(variables, SOURCES_HASH, SOURCES_HEADERS);
        if (!data || !data.data) return JSON.stringify({ streams: [], subtitles: [] });

        var sourceUrls = [];

        if (data.data._m && data.data.tobeparsed) {
            try {
                var decrypted = decodeTobeparsed(data.data.tobeparsed);
                var parsed = JSON.parse(decrypted);
                sourceUrls = (parsed && parsed.episode && parsed.episode.sourceUrls) || [];
            } catch(e) {
                console.log('Decryption error: ' + e);
            }
        } else if (data.data.episode && data.data.episode.sourceUrls) {
            sourceUrls = data.data.episode.sourceUrls;
        }

        if (!sourceUrls.length) return JSON.stringify({ streams: [], subtitles: [] });

        sourceUrls.sort(function(a, b) { return (b.priority || 0) - (a.priority || 0); });

        var streams = [];
        for (var i = 0; i < sourceUrls.length; i++) {
            var source = sourceUrls[i];
            if (!source.sourceUrl) continue;
            if (source.type === 'iframe') continue;
            if (source.sourceUrl.indexOf('tools.fast4speed.rsvp') !== -1) continue;

            var resolved = await resolveStreamUrl(source.sourceUrl);
            if (!resolved) continue;

            streams.push({
                title: source.sourceName || 'Server ' + (i + 1),
                streamUrl: resolved,
                headers: { 'Referer': ALLANIME_REFR + '/' }
            });
        }

        return JSON.stringify({ streams: streams, subtitles: [] });
    } catch(e) {
        console.log('extractStreamUrl error: ' + e);
        return JSON.stringify({ streams: [], subtitles: [] });
    }
}

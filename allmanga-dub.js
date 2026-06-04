// AllManga (DUB) Module
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

async function decodeTobeparsed(tobeparsed) {
    try {
        var b64 = tobeparsed;
        var pad = b64.length % 4;
        if (pad) b64 += '===='.slice(pad);
        var data = base64ToBytes(b64);
        // byte 0 is skipped, bytes 1-12 are IV, bytes 13+ are ciphertext+tag
        var iv = data.slice(1, 13);
        var ciphertext = data.slice(13);
        var keyBytes = hexToBytes(ALLANIME_KEY);
        var cryptoKey = await crypto.subtle.importKey(
            'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
        );
        var plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            ciphertext
        );
        return new TextDecoder().decode(plaintext);
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
                var decrypted = await decodeTobeparsed(data.data.tobeparsed);
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

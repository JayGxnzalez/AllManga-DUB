// AllManga (DUB) Module
// Uses AllAnime GraphQL API with XOR-decoded sourceUrls, dub-only

var GQL_URL = "https://api.allanime.day/api";
var SITE_URL = "https://allmanga.to";

var GQL_HEADERS = {
    "Origin": SITE_URL,
    "Referer": SITE_URL + "/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*"
};

async function soraFetch(url, options) {
    options = options || { headers: {}, method: "GET", body: null };
    try {
        if (typeof fetchv2 !== "undefined") {
            return await fetchv2(url, options.headers || {}, options.method || "GET", options.body || null, true, options.encoding || "utf-8");
        } else {
            return await fetch(url, options);
        }
    } catch(e) {
        try { return await fetch(url, options); } catch(err) { return null; }
    }
}

async function gqlFetch(query) {
    var res = await soraFetch(GQL_URL, {
        method: "POST",
        headers: GQL_HEADERS,
        body: JSON.stringify({ query: query })
    });
    if (!res) return null;
    try {
        var text = typeof res.text === "function" ? await res.text() : null;
        if (!text) return null;
        return JSON.parse(text);
    } catch(e) {
        console.log("gqlFetch parse error: " + e);
        return null;
    }
}

function decodeUrl(raw) {
    if (!raw) return raw;
    if (raw.indexOf("--") === 0) {
        try {
            var hex = raw.slice(2);
            var result = "";
            for (var i = 0; i < hex.length; i += 2) {
                result += String.fromCharCode(parseInt(hex.substr(i, 2), 16) ^ 56);
            }
            return result;
        } catch(e) {}
    }
    if (raw.indexOf("ap/") === 0) {
        try {
            var hex2 = raw.slice(3);
            var result2 = "";
            for (var j = 0; j < hex2.length; j += 2) {
                result2 += String.fromCharCode(parseInt(hex2.substr(j, 2), 16));
            }
            return result2;
        } catch(e) {}
    }
    return raw;
}

async function searchResults(keyword) {
    try {
        var query = '{shows(search:{sortBy:Latest_Update,query:"' + keyword + '"},limit:26,page:1,translationType:dub){edges{_id name englishName nativeName thumbnail availableEpisodes}}}';
        var data = await gqlFetch(query);
        if (!data || !data.data || !data.data.shows) return JSON.stringify([]);

        var edges = data.data.shows.edges;
        var results = [];
        for (var i = 0; i < edges.length; i++) {
            var show = edges[i];
            if (!show.availableEpisodes || !show.availableEpisodes.dub || show.availableEpisodes.dub === 0) continue;
            var title = show.englishName || show.name || "Unknown";
            var image = show.thumbnail || "";
            if (image && image.indexOf("http") !== 0) {
                image = "https://allanimenews.com/" + image.replace(/^\//, "");
            }
            results.push({
                title: title,
                image: image,
                href: "https://allmanga.to/anime/" + show._id
            });
        }
        return JSON.stringify(results);
    } catch(e) {
        console.log("searchResults error: " + e);
        return JSON.stringify([]);
    }
}

async function extractDetails(url) {
    try {
        var idMatch = url.match(/\/anime\/([^\/\?#]+)/);
        if (!idMatch) return JSON.stringify([{ description: "N/A", aliases: "N/A", airdate: "N/A" }]);
        var showId = idMatch[1];

        var query = '{show(_id:"' + showId + '"){name englishName nativeName description altNames airedStart airedEnd status genres}}';
        var data = await gqlFetch(query);
        if (!data || !data.data || !data.data.show) return JSON.stringify([{ description: "N/A", aliases: "N/A", airdate: "N/A" }]);

        var show = data.data.show;
        var description = show.description || "N/A";
        var aliases = (show.altNames && show.altNames.length > 0) ? show.altNames.join(", ") : (show.nativeName || "N/A");
        var airdate = "N/A";
        if (show.airedStart && show.airedStart.year) {
            airdate = show.airedStart.year + "";
            if (show.airedEnd && show.airedEnd.year) {
                airdate += " - " + show.airedEnd.year;
            }
        }

        return JSON.stringify([{
            description: description,
            aliases: aliases,
            airdate: airdate
        }]);
    } catch(e) {
        console.log("extractDetails error: " + e);
        return JSON.stringify([{ description: "N/A", aliases: "N/A", airdate: "N/A" }]);
    }
}

async function extractEpisodes(url) {
    try {
        var idMatch = url.match(/\/anime\/([^\/\?#]+)/);
        if (!idMatch) return JSON.stringify([]);
        var showId = idMatch[1];

        // Fetch show info to get dub episode count
        var showQuery = '{show(_id:"' + showId + '"){availableEpisodes}}';
        var showData = await gqlFetch(showQuery);
        var dubCount = 0;
        if (showData && showData.data && showData.data.show && showData.data.show.availableEpisodes) {
            dubCount = showData.data.show.availableEpisodes.dub || 0;
        }
        if (dubCount === 0) return JSON.stringify([]);

        // Fetch episode list
        var epQuery = '{episodeInfos(showId:"' + showId + '",episodeNumStart:0,episodeNumEnd:9999){episodeIdNum}}';
        var data = await gqlFetch(epQuery);
        if (!data || !data.data || !data.data.episodeInfos) return JSON.stringify([]);

        var eps = data.data.episodeInfos;
        eps.sort(function(a, b) { return (a.episodeIdNum || 0) - (b.episodeIdNum || 0); });

        // Only return up to dubCount episodes
        var results = [];
        for (var i = 0; i < eps.length && results.length < dubCount; i++) {
            var ep = eps[i];
            var epNum = ep.episodeIdNum;
            var epStr = (epNum % 1 === 0) ? String(Math.floor(epNum)) : String(epNum);
            results.push({
                href: showId + "|" + epStr,
                number: epNum
            });
        }
        return JSON.stringify(results);
    } catch(e) {
        console.log("extractEpisodes error: " + e);
        return JSON.stringify([]);
    }
}

async function extractStreamUrl(url) {
    try {
        var parts = url.split("|");
        if (parts.length < 2) return JSON.stringify({ streams: [], subtitles: [] });
        var showId = parts[0];
        var epNum = parts[1];

        var query = '{episode(showId:"' + showId + '",translationType:dub,episodeString:"' + epNum + '"){episodeString sourceUrls}}';
        var data = await gqlFetch(query);

        if (!data || !data.data || !data.data.episode) {
            return JSON.stringify({ streams: [], subtitles: [] });
        }

        var sourceUrls = data.data.episode.sourceUrls;
        if (!sourceUrls || sourceUrls.length === 0) {
            return JSON.stringify({ streams: [], subtitles: [] });
        }

        sourceUrls.sort(function(a, b) { return (b.priority || 0) - (a.priority || 0); });

        var streams = [];
        for (var i = 0; i < sourceUrls.length; i++) {
            var src = sourceUrls[i];
            if (!src || !src.url) continue;
            var decoded = decodeUrl(src.url);
            if (!decoded) continue;

            var srcType = (src.type || "").toLowerCase();
            if (srcType === "iframe") continue;

            var serverName = src.sourceName || "Server " + (i + 1);

            streams.push({
                title: serverName,
                streamUrl: decoded,
                headers: {
                    "Referer": SITE_URL + "/",
                    "Origin": SITE_URL
                }
            });
        }

        return JSON.stringify({ streams: streams, subtitles: [] });
    } catch(e) {
        console.log("extractStreamUrl error: " + e);
        return JSON.stringify({ streams: [], subtitles: [] });
    }
}

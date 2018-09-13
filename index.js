const OAuth = require("oauth-advanced");

function getAuthorisationUrl(confluenceURL, oauthKey, privateKey, returnURL, callback) {
	let oa = new OAuth(
		confluenceURL + "/wiki/plugins/servlet/oauth/request-token",
		confluenceURL + "/wiki/plugins/servlet/oauth/access-token",
		oauthKey,
		privateKey,
		"1.0",
		returnURL,
		"RSA-SHA1",
		null,
		{
			"Accept" : "application/json",
			"Content-Type": "application/json",
			"Data-Type": "json"
		}
	);

	process.env.confluenceOauth = JSON.stringify({
		confluenceURL: confluenceURL,
		oauthKey: oauthKey,
		privateKey: privateKey,
		returnURL: returnURL
	});

	oa.getOAuthRequestToken((error, oauthToken, oauthTokenSecret) => {
		if (error) {
			callback(error);
			return;
		}
		let authorizeURL = confluenceURL + "/wiki/plugins/servlet/oauth/authorize?oauth_token=" + oauthToken;
		process.env.confluenceOauth = JSON.stringify(Object.assign(JSON.parse(process.env.confluenceOauth), {oauthToken: oauthToken, oauthTokenSecret: oauthTokenSecret}));
		callback(null, authorizeURL, oauthToken, oauthTokenSecret);
	});
}

function getAccessToken(oauth_verifier, callback) {
	let oauthData = JSON.parse(process.env.confluenceOauth),
		oa = new OAuth(
			oauthData.confluenceURL + "/wiki/plugins/servlet/oauth/request-token",
			oauthData.confluenceURL + "/wiki/plugins/servlet/oauth/access-token",
			oauthData.oauthKey,
			oauthData.privateKey,
			"1.0",
			oauthData.returnURL,
			"RSA-SHA1",
			null,
			{
				"Accept" : "application/json",
				"Content-Type": "application/json",
				"Data-Type": "json"
			}
		);

	oa.getOAuthAccessToken(
		oauthData.oauthToken,
		oauthData.oauthTokenSecret,
		oauth_verifier,
		(error, oauthAccessToken, oauthAccessTokenSecret) => {
			if (error) {
				callback(error);
				return;
			}

			process.env.confluenceOauth = JSON.stringify(Object.assign(oauthData, {oauthAccessToken: oauthAccessToken, oauthAccessTokenSecret: oauthAccessTokenSecret}));

			callback(null, oauthAccessToken, oauthAccessTokenSecret)
		});
}

function makeApiCall(apiType, data, callback) {
	let oauthData = JSON.parse(process.env.confluenceOauth),
		oa = new OAuth(
			oauthData.confluenceURL + "/wiki/plugins/servlet/oauth/request-token",
			oauthData.confluenceURL + "/wiki/plugins/servlet/oauth/access-token",
			oauthData.oauthKey,
			oauthData.privateKey,
			"1.0",
			oauthData.returnURL,
			"RSA-SHA1",
			null,
			{
				"Accept" : "application/json",
				"Content-Type": "application/json",
				"Data-Type": "json"
			}
		),
		encodedUrl = oauthData.confluenceURL + "/wiki/rest/api/" + apiType + data;

	oa.get(
		encodeURI(encodedUrl),
		oauthData.oauthAccessToken,
		oauthData.oauthTokenSecret,
		"application/json",
		(err, confluenceResponse, body) => {
			if (err) {
				callback(err);
				return;
			}
			callback(null, confluenceResponse, body);
		});
}

module.exports = {
	getAuthorisationUrl: getAuthorisationUrl,
	getAccessToken: getAccessToken,
	makeApiCall: makeApiCall
};

function login(email, password, callback) {
	//
	// ** Please view the README before continuing! **
	//
	// https://github.com/okta-ciam-specialists/db-scripts-universal-directory/blob/main/README.md
	//

	const axios = require('axios');
	const qs = require('qs');

	const decodeJWT = async (jwtString) => {
		const parts = jwtString.split('.');

		if (Array.isArray(parts) && parts[1]) {
			const payloadString = Buffer.from(parts[1], 'base64').toString('utf8');

			if (payloadString) {
				return JSON.parse(payloadString);
			}
		}
		throw new Error('Unable to parse Okta JWT!');
	};

	const buildJWT = async () => {
		const jose = require('node-jose');
		const uuid = require('uuid');

		const { JWK_LOGIN: JWK, CLIENT_ID_LOGIN: clientId, AUD_LOGIN: aud } = configuration || {};

		const key = await (await jose.JWK.asKey(JSON.parse(JWK))).toJSON(true);

		const iat = Math.floor(new Date().getTime() / 1000);

		const exp = new Date((iat + 5 * 60) * 1000).getTime() / 1000;

		const claims = {
			aud,
			iat,
			exp,
			iss: clientId,
			sub: clientId,
			jti: uuid.v4(),
		};

		return await jose.JWS.createSign({ alg: 'RS256', format: 'compact' }, key)
			.update(Buffer.from(JSON.stringify(claims), 'utf8'))
			.final();
	};

	const handleAuth = async (username, password, callback) => {
		const { AUD_LOGIN: url, CLIENT_ID_LOGIN: client_id, SCOPES_LOGIN: scope } = configuration || {};

		if (!client_id || !url) {
			return callback(new Error('Must provide a client_id and url!'));
		}

		const formData = {
			username,
			password,
			grant_type: 'password',
			scope,
			client_id,
			client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
			client_assertion: `${await buildJWT()}`,
		};

		const options = {
			url,
			method: 'post',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			validateStatus: (status) => {
				return (status >= 200 && status < 300) || status === 400;
			},
			data: qs.stringify(formData),
		};

		const { status: statusCode, statusText, data } = await axios(options);

		if (statusCode === 400 && data && data.error === 'invalid_grant') {
			return callback(new WrongUsernameOrPasswordError());
		}

		if (!data) {
			return callback(new Error(`${statusCode} ${statusText} | ${data}`));
		}

		const { id_token } = data;

		if (!id_token) {
			return callback(new Error('No `id_token` received from Okta!'));
		}

		const {
			sub: oktaId,
			name,
			email,
			email_verified,
			given_name,
			family_name,
			nickname,
			picture,
			...rest
		} = await decodeJWT(id_token);

		const { ver, iss, aud, iat, exp, jti, amr, idp, auth_time, at_hash, ...meta } = rest;

		const profile = {
			id: `ud|${oktaId}`,
			given_name,
			family_name,
			email,
			email_verified,
			nickname,
			name,
			picture,
			user_metadata: {
				okta_profile: {
					...meta,
				},
			},
		};

		return callback(null, profile);
	};

	return handleAuth(email, password, callback).catch((error) =>
		callback(new Error(`Unable to complete login! [${error}]`))
	);
}

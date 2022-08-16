function changePassword(email, newPassword, callback) {
	//
	// ** Please view the README before continuing! **
	//
	// https://github.com/okta-ciam-specialists/db-scripts-universal-directory/blob/main/README.md
	//

	const axios = require('axios');

	const buildJWT = async (_configuration) => {
		const jose = require('node-jose');
		const uuid = require('uuid');

		const { JWK, CLIENT_ID: clientId, AUD: aud } = _configuration || configuration || {};

		const key = (await jose.JWK.asKey(JSON.parse(JWK))).toJSON(true);

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

	const getAuth = async () => {
		const qs = require('qs');

		const {
			AUD_USER_SERVICE: url,
			CLIENT_ID_USER_SERVICE: client_id,
			SCOPES_USER_SERVICE: scopes,
			JWK_USER_SERVICE: JWK,
		} = configuration || {};

		if (!client_id || !url) {
			throw new Error('Must provide a client_id and url!');
		}

		const jwt = await buildJWT({ JWK, CLIENT_ID: client_id, SCOPES: scopes, AUD: url });

		if (!jwt) {
			throw new Error('Unable to generate necessary auth!');
		}

		const formData = {
			grant_type: 'client_credentials',
			scope: Array.isArray(scopes) && scopes.length > 0 ? scopes.join(' ') : scopes,
			client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
			client_assertion: jwt,
		};

		const options = {
			url,
			method: 'post',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			data: qs.stringify(formData),
		};

		const { status: statusCode, statusText, data } = await axios(options);

		if (!data) {
			throw new Error(`${statusCode} ${statusText} | ${data}`);
		}

		const { access_token } = data;

		if (!access_token) {
			throw new Error('No `access_token` received from Okta!');
		}

		return access_token;
	};

	const getUserId = async (email) => {
		const { ISSUER } = configuration || {};

		const url = `${ISSUER}/api/v1/users/${email}`;

		const options = {
			url,
			method: 'get',
			headers: {
				Authorization: `Bearer ${await getAuth()}`,
			},
		};

		const { data } = await axios(options);

		if (data && data.id) {
			return data.id;
		}

		throw new Error('Unable to fetch user `id`!');
	};

	const handleChangePassword = async (email, newPassword, callback) => {
		const { ISSUER } = configuration || {};

		const url = `${ISSUER}/api/v1/users/${await getUserId(email)}`;

		const options = {
			url,
			method: 'post',
			headers: {
				Authorization: `Bearer ${await getAuth()}`,
			},
			data: {
				credentials: {
					password: {
						value: newPassword,
					},
				},
			},
		};

		const { status: statusCode, statusText, data } = await axios(options);

		if (statusCode === 200) {
			return callback(null, true);
		}

		throw new Error(`${statusCode} ${statusText} | ${data}`);
	};

	return handleChangePassword(email, newPassword, callback).catch((error) =>
		callback(new Error(`Unable to update password! [${error}]`))
	);
}

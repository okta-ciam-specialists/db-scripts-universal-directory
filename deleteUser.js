function remove(id, callback) {
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

	const getOptions = async (id) => {
		const { ISSUER } = configuration || {};

		let okta_id = id.split('|')[1];

		if (id.split('|')[0] === 'auth0') {
			okta_id = id.split('|')[2];
		}

		if (!okta_id) {
			throw new Error('Unable to parse Okta ID from provided CIC ID');
		}

		const url = `${ISSUER}/api/v1/users/${okta_id}`;

		return {
			url,
			method: 'delete',
			headers: {
				Authorization: `Bearer ${await getAuth()}`,
			},
		};
	};

	const callOkta = async (id) => {
		const { status: statusCode } = await axios(await getOptions(id));

		if (statusCode !== 204) {
			throw new Error('Something went wrong!');
		}

		return true;
	};

	const handleDeleteUser = async (id, callback) => {
		// Deactivate
		await callOkta(id);

		// Delete
		await callOkta(id);

		return callback(null);
	};

	return handleDeleteUser(id, callback).catch((error) => callback(new Error(`Unable to delete users! [${error}]`)));
}

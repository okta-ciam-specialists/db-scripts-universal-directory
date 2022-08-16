function create(user, callback) {
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

	const getUserStatus = async (email) => {
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
		console.log(data);
		if (data && data.profile) {
			const { status } = data.profile;

			if (status && status === 'DEPROVISIONED') {
				return data.id;
			}
		}

		return false;
	};

	const setPassword = async (id, newPassword) => {
		const { ISSUER } = configuration || {};

		const url = `${ISSUER}/api/v1/users/${id}`;

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

		if (statusCode === 200 && data && data.status === 'ACTIVE') {
			return true;
		}

		return false;
	};

	const reactivateUser = async (email, password) => {
		const id = await getUserStatus(email);

		if (!id) {
			return false;
		}

		const { ISSUER } = configuration || {};

		const url = `${ISSUER}/api/v1/users/${id}/lifecycle/activate?sendEmail=false`;

		const options = {
			url,
			method: 'post',
			headers: {
				Authorization: `Bearer ${await getAuth()}`,
			},
		};

		const { data } = await axios(options);

		if (data && data.activationUrl) {
			return await setPassword(id, password);
		}

		return false;
	};

	const handleCreateUser = async ({ email, password, ...rest }, callback) => {
		const { ISSUER } = configuration || {};

		const url = `${ISSUER}/api/v1/users?activate=true`;

		const options = {
			url,
			method: 'post',
			headers: {
				Authorization: `Bearer ${await getAuth()}`,
			},
			validateStatus: (status) => {
				return (status >= 200 && status < 300) || status === 400;
			},
			data: {
				profile: {
					email,
					login: email,
				},
				credentials: {
					password: {
						value: password,
					},
				},
			},
		};

		const { status: statusCode, statusText, data } = await axios(options);

		if (statusCode === 200 && data && data.status === 'ACTIVE') {
			return callback(null);
		}

		if (statusCode === 400 && data && data.errorSummary.endsWith('login')) {
			// /*
			// User already exists but we need to confirm if the user is in a `deprovisioned` state.

			// If the user is `deprovisioned`, they can be reactivated.
			// */

			// if (await reactivateUser(email, password)) {
			// 	return callback(null);
			// }

			return callback(new ValidationError('user_exists', 'The user already exists in Okta.'));
		}

		throw new Error(`${statusCode} ${statusText} | ${data}`);
	};

	return handleCreateUser(user, callback).catch((error) => callback(new Error(`Unable to create user! [${error}]`)));
}

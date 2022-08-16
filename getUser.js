function getByEmail(email, callback) {
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
			return callback(new Error('Must provide a client_id and url!'));
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
			return callback(new Error(`${statusCode} ${statusText} | ${data}`));
		}

		const { access_token } = data;

		if (!access_token) {
			return callback(new Error('No `access_token` received from Okta!'));
		}

		return access_token;
	};

	const handleGetUser = async (email, callback) => {
		const { ISSUER } = configuration || {};

		const url = `${ISSUER}/api/v1/users/${email}`;

		const options = {
			url,
			method: 'get',
			headers: {
				Authorization: `Bearer ${await getAuth()}`,
			},
			validateStatus: (status) => {
				return (status >= 200 && status < 300) || status === 404;
			},
		};

		const { status: statusCode, statusText, data } = await axios(options);

		if (statusCode === 404) {
			return callback(null);
		}

		if (!data) {
			return callback(new Error(`${statusCode} ${statusText} | ${data}`));
		}

		const { id, type, profile: userProfile, credentials, _links, status: userStatus, ...rest } = data;

		/*
		User has been deleted by CIC db script. We will consider the user to not exist
		in this script and handle it appropriately in the `create` script.
		*/
		// if (userStatus && userStatus === 'DEPROVISIONED') {
		// 	console.log(userStatus)
		// 	return callback(null);
		// }

		const {
			email: _email,
			nickName: nickname,
			displayName: name,
			firstName: given_name,
			lastName: family_name,
			...restProfile
		} = userProfile;

		const result = {
			id: `ud|${id}`,
			given_name,
			family_name,
			email: _email,
			nickname,
			name,
			user_metadata: {
				okta_profile: {
					...rest,
					...restProfile,
				},
			},
		};

		return callback(null, result);
	};

	return handleGetUser(email, callback).catch((error) => callback(new Error(`Unable to fetch user! [${error}]`)));
}

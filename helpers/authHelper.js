import bcrypt from 'bcrypt';
import crypto from 'crypto';
import fs from 'fs';
import oauthPlugin from 'fastify-oauth2';

import { fileURLToPath } from 'url';
import { join } from 'path';
const __dirname = fileURLToPath(new URL('.', import.meta.url));

// use config file location
const configFilePath = join(__dirname, '..', '.authConfig.json');

// use config file (if present) or ENV variables
const CONFIG = fs.existsSync(configFilePath)
	? JSON.parse(fs.readFileSync(configFilePath))
	: {
			provider: process.env.PROVIDER,
			loginPath: process.env.LOGIN_PATH,
			callback: process.env.CALLBACK,
			schema: process.env.SCHEMA,
			table: process.env.TABLE,
			salt_rounds: process.env.SALT_ROUNDS,
			logout: process.env.LOGOUT,
			client: {
				id: process.env.CLIENT_ID,
				secret: process.env.CLIENT_SECRET,
			},
	  };

/**
 * Create the schema and table for the authentication tokens
 * @param {*} request
 * @param {*} response
 * @param {*} hdbCore
 * @param {*} logger
 * @returns
 */
async function setupSchema(request, response, hdbCore, logger) {
	logger.notify('Creating HDB Auth Schema');
	try {
		await hdbCore.requestWithoutAuthentication({
			body: {
				operation: 'create_schema',
				schema: CONFIG.schema,
			},
		});
		logger.notify('HDB Auth Schema has been created');
	} catch (error) {
		logger.notify('HDB Auth Schema already exists');
	}

	logger.notify('Create HDB Auth Table');
	try {
		await hdbCore.requestWithoutAuthentication({
			body: {
				operation: 'create_table',
				schema: CONFIG.schema,
				table: CONFIG.table,
				hash_attribute: 'user',
			},
		});
		logger.notify('HDB Auth Table has been created');
	} catch (error) {
		logger.notify('HDB Auth Table already exists');
	}

	return response.code(200).send('HDB Auth has been setup');
}

const loadRoutes = async ({ server, hdbCore, logger }) => {
	server.register(oauthPlugin, {
		name: 'githubOAuth2',
		credentials: {
			client: CONFIG.client,
			auth: oauthPlugin[CONFIG.provider],
		},
		// register a server url to start the redirect flow
		startRedirectPath: CONFIG.loginPath,
		// facebook redirect here after the user login
		callbackUri: CONFIG.callback,
	});

	const callback = CONFIG.callback.split('/').pop();
	server.get(`/${callback}`, async function (request, reply) {
		const token = await this.githubOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);

		const hdbToken = await new Promise((resolve) => {
			crypto.randomBytes(12, (error, buffer) => {
				resolve(buffer.toString('hex'));
			});
		});

		const hdbTokenUser = await new Promise((resolve) => {
			crypto.randomBytes(6, (error, buffer) => {
				resolve(buffer.toString('hex'));
			});
		});

		const hashedToken = bcrypt.hashSync(hdbToken, CONFIG.salt_rounds);

		await hdbCore.requestWithoutAuthentication({
			body: {
				operation: 'insert',
				schema: CONFIG.schema,
				table: CONFIG.table,
				records: [{ user: hdbTokenUser, token: hashedToken }],
			},
		});

		return `${hdbTokenUser}.${hdbToken}`;
		reply.send({ access_token: token.access_token });
	});

	server.get(`/${CONFIG.logout}`, async function (request, reply) {
		const userToken = request.headers.authorization;
		const [user, token] = userToken.split('.');

		const results = await hdbCore.requestWithoutAuthentication({
			body: {
				operation: 'search_by_hash',
				schema: CONFIG.schema,
				table: CONFIG.table,
				hash_values: [user],
				get_attributes: ['token'],
			},
		});

		for (const result of results) {
			const hashedToken = result.token;
			if (bcrypt.compareSync(token, hashedToken)) {
				await hdbCore.requestWithoutAuthentication({
					body: {
						operation: 'delete',
						schema: CONFIG.schema,
						table: CONFIG.table,
						hash_values: [user],
					},
				});
			}
		}

		return reply.code(200).send('Logout Successful');
	});
};

const validate = async (request, response, next, hdbCore, logging) => {
	const userToken = request.headers.authorization;
	const [user, token] = userToken.split('.');
	try {
		const results = await hdbCore.requestWithoutAuthentication({
			body: {
				operation: 'search_by_hash',
				schema: CONFIG.schema,
				table: CONFIG.table,
				hash_values: [user],
				get_attributes: ['token'],
			},
		});
		if (!results.length) {
			return response.code(401).send('HDB Token Error');
		}

		const { token: hashedToken } = results[0];

		if (!bcrypt.compareSync(token, hashedToken)) {
			return response.code(401).send('HDB Token Error');
		}

		if (!request.body) {
			request.body = {};
		}
		request.body.hdb_user = { role: { permission: { super_user: true } } };
		return next();
	} catch (error) {
		console.log('error', error);
		return response.code(500).send('HDB Token Error');
	}
};

export default { setupSchema, loadRoutes, validate };

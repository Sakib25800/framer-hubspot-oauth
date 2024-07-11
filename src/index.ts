import { generateRandomId } from './generateRandomId';
import { getHTMLTemplate } from './getHTMLTemplate';

async function handleRequest(request: Request, env: Env) {
	const requestUrl = new URL(request.url);

	// Generate an authorization URL to login into the provider, and a set of
	// read and write keys for retrieving the access token later on.
 
	// Once the user has been authorized via login page, the provider will
	// redirect them back this URL with an access code (not an access token) and
	// the write key we stored in the state param.
	if (request.method === 'GET' && requestUrl.pathname.startsWith('/redirect')) {
		const authorizationCode = requestUrl.searchParams.get('code');
		const writeKey = requestUrl.searchParams.get('state');

		if (!authorizationCode) {
			return new Response('Missing authorization code URL param', {
				status: 400,
			});
		}

		if (!writeKey) {
			return new Response('Missing state URL param', {
				status: 400,
			});
		}

		// Proof required to exchange for tokens
		const exchangeProof = {
			grant_type: 'authorization_code',
			client_id: env.CLIENT_ID,
			client_secret: env.CLIENT_SECRET,
			redirect_uri: env.REDIRECT_URI,
			code: authorizationCode,
		};

		const tokenResponse = await fetch(env.TOKEN_ENDPOINT, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams(exchangeProof).toString(),
		});

		if (tokenResponse.status !== 200) {
			return new Response(tokenResponse.statusText, {
				status: tokenResponse.status,
			});
		}

		const readKey = await env.hubspotOAuthStore.get(`readKey:${writeKey}`);

		if (!readKey) {
			return new Response('No read key found in storage', {
				status: 400,
			});
		}

		// Store the tokens temporarily inside a key value store. This will be
		// retrieved when the plugin polls for them.
		const tokens = (await tokenResponse.json()) as unknown;
		env.hubspotOAuthStore.put(`tokens:${readKey}`, JSON.stringify(tokens), {
			// TODO: Change back to 300
			expirationTtl: 900,
		});

		return new Response(getHTMLTemplate('Authentication successful! You can close this window and return to Framer.'), {
			headers: {
				'Content-Type': 'text/html',
			},
		});
	}

	if (request.method === 'POST' && requestUrl.pathname.startsWith('/poll')) {
		const readKey = requestUrl.searchParams.get('readKey');

		if (!readKey) {
			return new Response('Missing read key URL param', {
				status: 400,
				headers: {
					'Access-Control-Allow-Origin': env.PLUGIN_URI,
				},
			});
		}

		const tokens = await env.hubspotOAuthStore.get(`tokens:${readKey}`);

		if (!tokens) {
			return new Response(null, {
				status: 404,
				headers: { 'Access-Control-Allow-Origin': env.PLUGIN_URI },
			});
		}

		// Even though the tokens have an expiry, it's important to delete them on
		// our side to reduce the reliability of storing user's sensitive data.
		await env.hubspotOAuthStore.delete(`tokens:${readKey}`);

		return new Response(tokens, {
			headers: {
				'Content-Type': 'application/json',
				'Access-Control-Allow-Origin': env.PLUGIN_URI,
			},
		});
	}

	if (request.method === 'POST' && requestUrl.pathname.startsWith('/refresh')) {
		const refreshToken = requestUrl.searchParams.get('code');

		if (!refreshToken) {
			return new Response('Missing refresh token URL param', {
				status: 400,
				headers: {
					'Access-Control-Allow-Origin': env.PLUGIN_URI,
				},
			});
		}

		// Proof required to exchange for new tokens
		const exchangeProof = {
			grant_type: 'refresh_token',
			client_id: env.CLIENT_ID,
			client_secret: env.CLIENT_SECRET,
			redirect_uri: env.REDIRECT_URI,
			refresh_token: refreshToken,
		};

		const refreshResponse = await fetch(env.TOKEN_ENDPOINT, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams(exchangeProof).toString(),
		});

		if (refreshResponse.status !== 200) {
			return new Response(refreshResponse.statusText, {
				status: refreshResponse.status,
				headers: {
					'Access-Control-Allow-Origin': env.PLUGIN_URI,
				},
			});
		}

		const tokens = await refreshResponse.json();
		return new Response(JSON.stringify(tokens), {
			headers: {
				'Content-Type': 'application/json',
				'Access-Control-Allow-Origin': env.PLUGIN_URI,
			},
		});
	}

	if (request.method === 'GET' && requestUrl.pathname === '/') {
		return new Response('✅ OAuth Worker is up and running!');
	}

	return new Response('Page not found', {
		status: 404,
		headers: {
			'Access-Control-Allow-Origin': env.PLUGIN_URI,
		},
	});
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		return handleRequest(request, env).catch((error) => {
			const message = error instanceof Error ? error.message : 'Unknown';

			return new Response(`😔 Internal error: ${message}`, {
				status: 500,
				headers: {
					'Access-Control-Allow-Origin': env.PLUGIN_URI,
				},
			});
		});
	},
};

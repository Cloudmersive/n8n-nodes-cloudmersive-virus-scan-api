import {
	ICredentialType,
	INodeProperties,
	IAuthenticateGeneric,
} from 'n8n-workflow';

export class CloudmersiveApi implements ICredentialType {
	name = 'cloudmersiveApi';
	displayName = 'Cloudmersive API';
	documentationUrl = 'https://api.cloudmersive.com/docs/virus';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'Your Cloudmersive API Key',
		},
		{
			displayName: 'Environment',
			name: 'environment',
			type: 'options',
			default: 'test',
			options: [
				{ name: 'Test', value: 'test', description: 'URL: https://testapi.cloudmersive.com' },
				{ name: 'Production', value: 'prod', description: 'URL: https://api.cloudmersive.com' },
			],
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Apikey: '={{$credentials.apiKey}}',
			},
		},
	};
}

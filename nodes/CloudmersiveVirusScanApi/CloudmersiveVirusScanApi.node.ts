import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	JsonObject,
	IHttpRequestOptions,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionType } from 'n8n-workflow';

import {
	applyAdvancedHeaders,
	buildFormFile,
	getBaseUrl,
} from './GenericFunctions';

export class CloudmersiveVirusScanApi implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Cloudmersive Virus Scan',
		name: 'cloudmersiveVirusScanApi',
		icon: 'file:cloudmersive.svg',
		group: ['transform'],
		version: 1,
		description: 'Scan files, websites, and cloud storage for malware via Cloudmersive',
		defaults: { name: 'Cloudmersive Virus Scan' },
		// TS requires NodeConnectionType; linter prefers ['main'], so disable rule for these two lines.
		// eslint-disable-next-line n8n-nodes-base/node-class-description-inputs-wrong-regular-node
		inputs: [NodeConnectionType.Main],
		// eslint-disable-next-line n8n-nodes-base/node-class-description-outputs-wrong
		outputs: [NodeConnectionType.Main],
		credentials: [{ name: 'cloudmersiveApi', required: true }],
		properties: [
			/* Resource */
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				options: [
					{ name: 'File', value: 'file' },
					{ name: 'Website', value: 'website' },
				],
				default: 'file',
				noDataExpression: true,
			},

			/* Operation per resource */
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['file'] } },
				options: [
					{
						name: 'Scan',
						value: 'scan',
						description: 'Scan a file for viruses',
						action: 'Scan a file',
					},
					{
						name: 'Advanced Scan',
						value: 'scanAdvanced',
						description: 'Advanced file scan with 360° content protection',
						action: 'Advanced scan a file',
					},
				],
				default: 'scan',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['website'] } },
				options: [
					{
						name: 'Scan',
						value: 'scan',
						description: 'Scan a website for malicious content and threats',
						action: 'Scan a website',
					},
				],
				default: 'scan',
			},

			/* FILE */
			{
				displayName: 'Binary Property Name',
				name: 'binaryPropertyName',
				type: 'string',
				default: 'data',
				required: true,
				placeholder: 'data',
				description: 'Name of the binary property that contains the file to scan',
				displayOptions: { show: { resource: ['file'] } },
			},
			{
				displayName: 'Override File Name',
				name: 'overrideFileName',
				type: 'string',
				default: '',
				placeholder: 'example.pdf',
				description: 'Optional: original file name header for advanced scan',
				displayOptions: {
					show: { resource: ['file'], operation: ['scanAdvanced'] },
				},
			},
			{
				displayName: 'Advanced Controls',
				name: 'advancedControls',
				type: 'collection',
				placeholder: 'Add options',
				displayOptions: {
					show: {
						resource: ['file'],
						operation: ['scanAdvanced'],
					},
				},
				default: {},
				options: [
					{ displayName: 'Allow Executables', name: 'allowExecutables', type: 'boolean', default: false },
					{ displayName: 'Allow HTML', name: 'allowHtml', type: 'boolean', default: false },
					{ displayName: 'Allow Insecure Deserialization', name: 'allowInsecureDeserialization', type: 'boolean', default: false },
					{ displayName: 'Allow Invalid Files', name: 'allowInvalidFiles', type: 'boolean', default: false },
					{ displayName: 'Allow Macros', name: 'allowMacros', type: 'boolean', default: false },
					{ displayName: 'Allow OLE Embedded Object', name: 'allowOleEmbeddedObject', type: 'boolean', default: false },
					{ displayName: 'Allow Password-Protected Files', name: 'allowPasswordProtectedFiles', type: 'boolean', default: false },
					{ displayName: 'Allow Scripts', name: 'allowScripts', type: 'boolean', default: false },
					{ displayName: 'Allow Unsafe Archives', name: 'allowUnsafeArchives', type: 'boolean', default: false },
					{ displayName: 'Allow XML External Entities', name: 'allowXmlExternalEntities', type: 'boolean', default: false },
					{
						displayName: 'Options',
						name: 'optionsList',
						type: 'multiOptions',
						default: [],
						options: [
							{ name: 'blockInvalidUris', value: 'blockInvalidUris' },
							{ name: 'blockOfficeXmlOleEmbeddedFile', value: 'blockOfficeXmlOleEmbeddedFile' },
							{ name: 'permitAuthenticodeSignedExecutables', value: 'permitAuthenticodeSignedExecutables' },
							{ name: 'permitJavascriptAndHtmlInPDFs', value: 'permitJavascriptAndHtmlInPDFs' },
							{ name: 'scanMultipartFile', value: 'scanMultipartFile' },
						],
						description:
							'Additional API options (become the comma-separated "options" header)',
					},
					{
						displayName: 'Restrict File Types',
						name: 'restrictFileTypes',
						type: 'string',
						default: '',
						placeholder: '.pdf,.docx,.png',
						description:
							'Comma-separated extensions to allow (uses content verification)',
					},
				],
			},

			/* WEBSITE */
			{
				displayName: 'URL',
				name: 'url',
				type: 'string',
				default: '',
				placeholder: 'https://example.com',
				required: true,
				description: 'Website URL to scan (http/https)',
				displayOptions: { show: { resource: ['website'], operation: ['scan'] } },
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const baseUrl = await getBaseUrl.call(this);

		for (let i = 0; i < items.length; i++) {
		 try {
				const resource = this.getNodeParameter('resource', i) as string;
				const operation = this.getNodeParameter('operation', i) as string;

				let method: IHttpRequestOptions['method'] = 'POST';
				let uriPath = '';
				const headers: IDataObject = {};
				const qs: IDataObject = {};
				let body: IDataObject | undefined;
				let formData: IDataObject | undefined;

				/* FILE */
				if (resource === 'file') {
					const binaryPropertyName = this.getNodeParameter('binaryPropertyName', i) as string;

					if (operation === 'scan') {
						uriPath = '/virus/scan/file';
						formData = await buildFormFile.call(this, i, binaryPropertyName, 'inputFile');
					} else if (operation === 'scanAdvanced') {
						uriPath = '/virus/scan/file/advanced';
						formData = await buildFormFile.call(this, i, binaryPropertyName, 'inputFile');

						const overrideFileName = this.getNodeParameter('overrideFileName', i, '') as string;
						if (overrideFileName) headers['fileName'] = overrideFileName;

						const adv = this.getNodeParameter('advancedControls', i, {}) as IDataObject;
						applyAdvancedHeaders(headers, adv);
					}
				}

				/* WEBSITE */
				else if (resource === 'website') {
					uriPath = '/virus/scan/website';
					const url = this.getNodeParameter('url', i) as string;
					body = { Url: url };
				}

				const options: IHttpRequestOptions = {
					method,
					url: `${baseUrl}${uriPath}`,
					json: true,
				};
				if (Object.keys(headers).length) options.headers = headers;
				if (Object.keys(qs).length) options.qs = qs;

				if (formData !== undefined) (options as any).formData = formData;
				else if (body !== undefined) options.body = body;

				const responseData = await this.helpers.requestWithAuthentication.call(
					this,
					'cloudmersiveApi',
					options,
				);

				returnData.push({ json: responseData as IDataObject });
			} catch (error) {
				throw new NodeApiError(this.getNode(), error as JsonObject);
			}
		}

		return [returnData];
	}
}

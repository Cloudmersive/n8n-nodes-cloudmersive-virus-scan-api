import type { IExecuteFunctions, IDataObject } from 'n8n-workflow';

/** Resolve base URL from credentials (test vs. prod). */
export async function getBaseUrl(this: IExecuteFunctions): Promise<string> {
	const creds = (await this.getCredentials('cloudmersiveApi')) as IDataObject;
	const env = (creds.environment ?? 'test') as string;
	const host = env === 'prod' ? 'api.cloudmersive.com' : 'testapi.cloudmersive.com';
	return `https://${host}`;
}

/** Convert an array of option flags into the comma-separated header string. */
export function joinOptionsHeader(optionsArray?: string[] | null): string | undefined {
	if (!optionsArray || optionsArray.length === 0) return undefined;
	return optionsArray.join(',');
}

/** Assign advanced boolean headers if present in the provided collection. */
export function applyAdvancedHeaders(headers: IDataObject, adv: IDataObject = {}): void {
	const keys = [
		'allowExecutables',
		'allowInvalidFiles',
		'allowScripts',
		'allowPasswordProtectedFiles',
		'allowMacros',
		'allowXmlExternalEntities',
		'allowInsecureDeserialization',
		'allowHtml',
		'allowUnsafeArchives',
		'allowOleEmbeddedObject',
	];
	for (const k of keys) {
		if (adv[k] !== undefined) {
			headers[k] = adv[k];
		}
	}
	if (adv.restrictFileTypes) headers['restrictFileTypes'] = adv.restrictFileTypes;
	if (adv.optionsList && Array.isArray(adv.optionsList)) {
		const joined = joinOptionsHeader(adv.optionsList as string[]);
		if (joined) headers['options'] = joined;
	}
}

/** Build a multipart form-data field for uploading a binary file. */
export async function buildFormFile(
	this: IExecuteFunctions,
	itemIndex: number,
	binaryPropertyName: string,
	formFieldName: string,
): Promise<IDataObject> {
	const binary = this.helpers.assertBinaryData(itemIndex, binaryPropertyName);
	const buffer = await this.helpers.getBinaryDataBuffer(itemIndex, binaryPropertyName);
	return {
		[formFieldName]: {
			value: buffer,
			options: {
				filename: binary.fileName ?? 'file',
				contentType: binary.mimeType,
			},
		},
	};
}

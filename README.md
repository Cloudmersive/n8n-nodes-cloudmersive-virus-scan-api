# n8n-nodes-_node-name_

This is an n8n community node. It lets you use Cloudmersive Virus Scan API in your n8n workflows.

Cloudmersive Virus Scan API enables you to scan files and content for viruses and leverage continuously updated signatures for millions of threats, and advanced high-performance scanning capabilities.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/reference/license/) workflow automation platform.

[Installation](#installation)  
[Operations](#operations)  
[Credentials](#credentials)
[Compatibility](#compatibility)  
[Usage](#usage)
[Resources](#resources)  

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation.

## Operations

This node currently supports the following resources and operations:

### File

* **Scan** — Scan a binary file from the incoming item.
* **Advanced Scan** — Scan a binary file with 360° content protection controls (block macros, scripts, restrict file types, etc.).

  * Optional: **Override File Name** header for content-aware scanning.

**Required input**

* *Binary Property Name* — defaults to `data`.

**Advanced controls** (Advanced Scan):

* Booleans: `allowExecutables`, `allowHtml`, `allowInsecureDeserialization`, `allowInvalidFiles`, `allowMacros`, `allowOleEmbeddedObject`, `allowPasswordProtectedFiles`, `allowScripts`, `allowUnsafeArchives`, `allowXmlExternalEntities`
* Multi-select **Options** (sent as a comma-separated `options` header):

  * `blockInvalidUris`, `blockOfficeXmlOleEmbeddedFile`, `permitAuthenticodeSignedExecutables`, `permitJavascriptAndHtmlInPDFs`, `scanMultipartFile`
* **Restrict File Types** — comma-separated extensions to permit (e.g., `.pdf,.docx,.png`).

### Website

* **Scan** — Scan a website URL for malicious content and threats.
  **Input**: `URL` (http/https)

### Azure Blob

* **Scan** — Scan a single blob.
* **Advanced Scan** — Advanced scan of a single blob.
* **Advanced Scan via Batch Job** — Submit an async batch job for a single blob and poll its status with the *Batch Job → Get Status* operation.

**Inputs**: `Connection String`, `Container Name`, `Blob Path` (e.g., `hello.pdf` or `/folder/sub/world.pdf`)

### AWS S3

* **Scan** — Scan a single object.
* **Advanced Scan** — Advanced scan of a single object.

**Inputs**: `Access Key`, `Secret Key`, `Bucket Region`, `Bucket Name`, `Key Name` (use `base64:` prefix if Unicode), optional `Role ARN`.

### GCP Storage

* **Scan** — Scan a single object.
* **Advanced Scan** — Advanced scan of a single object.

**Inputs**:

* `Bucket Name`, `Object Name` (use `base64:` prefix if Unicode)
* `JSON Credential (Binary)` — name of the binary property containing your GCP service account JSON (e.g., `gcpCredentials`)

### SharePoint Online Site

* **Scan** — Scan a file in a site drive by path.
* **Advanced Scan** — Advanced scan by file path and/or `Item ID`.

**Inputs**:

* Auth: `Client ID`, `Client Secret`, `SharePoint Domain` (e.g., `mydomain.sharepoint.com`), `Site ID (GUID)`, optional `Tenant ID`
* Path fields:

  * *Scan*: `File Path` (e.g., `hello.pdf` or `/folder/sub/world.pdf`)
  * *Advanced Scan*: `File Path` (optional), `Item ID` (optional) — either can be used; `base64:` prefix supported for Unicode paths.

### Cloud Storage Batch Job

* **Get Status** — Query the status/result of an async batch job.
  **Input**: `Async Job ID`

## Credentials

The Cloudmersive Virus Scan API is free to use.  You can get a free API key that does not expire by going to [Cloudmersive](https://portal.cloudmersive.com/signup) and signing up.

## Compatibility

_State the minimum n8n version, as well as which versions you test against. You can also include any known version incompatibility issues._

## Usage

To use the service, simply drop the node into your flow and pass in a file as the data parameter.  Look at the CleanResult attribute returned as part of the output to confirm if your file passed the scan.

## Resources

* [n8n community nodes documentation](https://docs.n8n.io/integrations/#community-nodes)
* [Cloudmersive Virus Scan API Documentation](https://api.cloudmersive.com/docs/virus.asp)


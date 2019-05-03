<Query Kind="Program">
  <NuGetReference>Microsoft.AspNet.WebApi.Client</NuGetReference>
  <NuGetReference>System.IdentityModel.Tokens.Jwt</NuGetReference>
  <Namespace>Newtonsoft.Json</Namespace>
  <Namespace>Newtonsoft.Json.Linq</Namespace>
  <Namespace>System.Net</Namespace>
  <Namespace>System.Net.Http</Namespace>
  <Namespace>System.Net.Http.Headers</Namespace>
  <Namespace>System.Security.Authentication</Namespace>
  <Namespace>System.Threading.Tasks</Namespace>
  <Namespace>Microsoft.IdentityModel.Tokens</Namespace>
  <Namespace>System.Security.Cryptography.X509Certificates</Namespace>
  <Namespace>System.Security.Cryptography</Namespace>
  <Namespace>System.Net.Http.Formatting</Namespace>
</Query>

async Task Main(string[] args)
{
	var discoveryClient = new DiscoveryClient(new Uri("https://hc2935.hqcatalyst.local/DiscoveryService/v1"));
	
	using(var metadata = new MetadataService2Client(discoveryClient))
	{
		var response = await metadata.SummaryDataMarts();
		response.Dump();
	}
	
	using(var auth = new AuthorizationClient(discoveryClient))
	{
		var result = await auth.GetRoles("dos", "datamart");
		result.Dump();
	}
}

public class MetadataService2Client : FabricClient
{
	private const string Scope = "dos/metadata dos/metadata.serviceAdmin";
	public MetadataService2Client(DiscoveryClient discoveryClient) : base(discoveryClient, DosService.MetadataService2, Scope)
	{
	}

	public async Task<string> SummaryDataMarts()
	{
		return await this.GetAsync($"/SummaryDataMarts");
	}
}

public class DiscoveryClient
{
	private readonly Uri discoveryUri;

	public DiscoveryClient(Uri discoveryUri)
	{
		this.discoveryUri = discoveryUri;
	}

	public async Task<Uri> GetService(DosService service)
	{
		string serviceName;
		int version = 1;
		switch (service)
		{
			case DosService.Atlas4:
				serviceName = "Atlas4";
				break;
			case DosService.EDWConsole:
				serviceName = "EDW Console";
				break;
			case DosService.DataProcessingService1:
				serviceName = "DataProcessingService";
				break;
			case DosService.DataProcessingService2:
				serviceName = "DataProcessingService";
				version = 2;
				break;
			case DosService.MetadataService1:
				serviceName = "MetadataService";
				break;
			case DosService.MetadataService2:
				serviceName = "MetadataService";
				version = 2;
				break;
			case DosService.SearchService:
				serviceName = "SearchService";
				break;
			case DosService.IdentityService:
				serviceName = "IdentityService";
				break;
			case DosService.IdentityProviderSearchService:
				serviceName = "IdentityProviderSearchService";
				break;
			case DosService.AuthorizationService:
				serviceName = "AuthorizationService";
				break;
			case DosService.AccessControl:
				serviceName = "AccessControl";
				break;
			case DosService.TerminologyService:
				serviceName = "TerminologyService";
				break;
			case DosService.AnalyticsService:
				serviceName = "AnalyticsService";
				break;
			case DosService.UserConfigService:
				serviceName = "UserConfigService";
				break;
			case DosService.OperationsConsole:
				serviceName = "OperationsConsole";
				break;
			case DosService.Atlas:
				serviceName = "Atlas";
				break;
			case DosService.IDEA:
				serviceName = "IDEA";
				break;
			case DosService.AdministrationService:
				serviceName = "AdministrationService";
				break;
			default:
				throw new InvalidOperationException("service not valid");
		}

		var client = CustomHttpClientFactory.CreateClient();
		var response = await client.GetAsync($"{this.discoveryUri}/Services(ServiceName='{serviceName}', Version={version})?$select=ServiceUrl");
		var json = await response.Content.ReadAsAsync<DiscoveryODataResult>();
		return json.ServiceUrl;
	}

	private class DiscoveryODataResult
	{
		public Uri ServiceUrl {get; set;}
	}
}

public enum DosService
{
	Atlas4,
	EDWConsole,
	DataProcessingService1,
	DataProcessingService2,
	MetadataService1,
	MetadataService2,
	SearchService,
	IdentityService,
	IdentityProviderSearchService,
	AuthorizationService,
	AccessControl,
	TerminologyService,
	AnalyticsService,
	UserConfigService,
	OperationsConsole,
	Atlas,
	IDEA,
	AdministrationService
}

public class ManageClients : FabricClient
{
	private const string Scope = "fabric/identity.manageresources";

	public ManageClients(DiscoveryClient discoveryClient) : base(discoveryClient, DosService.IdentityService, Scope)
	{
	}

	public async Task<Client> GetClient(string clientId)
	{
		return await this.GetAsync<Client>($"/api/client/{clientId}");
	}

	public async Task<Client> PostClient(Client client)
	{
		return await this.PostAsync<Client>($"/api/client", client);
	}

	public async Task<Client> PutClient(Client client)
	{
		return await this.PutAsync<Client>($"/api/client/{client.clientId}", client);
	}

	public async Task<object> GetUsers(string clientId, string user)
	{
		return await this.GetAsync<object>($"/api/users", new Dictionary<string, string>() { { "clientId", user } });
	}

	public class Client
	{
		public bool enabled { get; set; }
		public string clientId { get; set; }
		public object clientSecret { get; set; }
		public bool requireClientSecret { get; set; }
		public List<string> allowedGrantTypes { get; set; }
		public bool requirePkce { get; set; }
		public bool allowPlainTextPkce { get; set; }
		public List<string> redirectUris { get; set; }
		public List<string> allowedScopes { get; set; }
		public bool allowOfflineAccess { get; set; }
		public bool allowAccessTokensViaBrowser { get; set; }
		public string protocolType { get; set; }
		public List<string> postLogoutRedirectUris { get; set; }
		public bool enableLocalLogin { get; set; }
		public List<object> identityProviderRestrictions { get; set; }
		public object logoutUri { get; set; }
		public bool logoutSessionRequired { get; set; }
		public int identityTokenLifetime { get; set; }
		public int accessTokenLifetime { get; set; }
		public int authorizationCodeLifetime { get; set; }
		public int absoluteRefreshTokenLifetime { get; set; }
		public int slidingRefreshTokenLifetime { get; set; }
		public int refreshTokenUsage { get; set; }
		public int refreshTokenExpiration { get; set; }
		public bool updateAccessTokenClaimsOnRefresh { get; set; }
		public int accessTokenType { get; set; }
		public bool includeJwtId { get; set; }
		public List<string> allowedCorsOrigins { get; set; }
		public List<object> claims { get; set; }
		public bool alwaysSendClientClaims { get; set; }
		public bool alwaysIncludeUserClaimsInIdToken { get; set; }
		public bool prefixClientClaims { get; set; }
		public bool requireConsent { get; set; }
		public bool allowRememberConsent { get; set; }
		public string clientName { get; set; }
		public object clientUri { get; set; }
		public object logoUri { get; set; }
	}
}

public class AuthorizationClient : FabricClient
{
	private const string Scope = "fabric/authorization.read fabric/authorization.write fabric/authorization.manageclients fabric/authorization.dos.write";

	public AuthorizationClient(DiscoveryClient discoveryClient) : base(discoveryClient, DosService.AuthorizationService, Scope)
	{
	}

	public async Task<Permission> CreatePermission(Permission permission)
	{
		return await this.PostAsync("/permissions", permission);
	}

	public async Task<bool> DeletePermission(string permissionId)
	{
		return await this.DeleteAsync($"/permissions/{permissionId}");
	}

	public async Task<List<Permission>> GetPermissions(string grain, string securableItem, string name = null)
	{
		return await this.GetAsync<List<Permission>>($"/permissions/{grain}/{securableItem}/{name}");
	}

	public async Task<Role> CreateRole(Role role)
	{
		return await this.PostAsync("/roles", role);
	}

	public async Task<bool> DeleteRole(string roleId)
	{
		//await this.DeleteAsync($"/roles/{roleId}/permissions");
		return await this.DeleteAsync($"/roles/{roleId}");
	}

	public async Task<List<Role>> GetRoles(string grain, string securableItem, string name = null)
	{
		return await this.GetAsync<List<Role>>($"/roles/{grain}/{securableItem}/{name}");
	}

	public async Task<bool> AddPermissionToRole(Permission[] permissions, string roleId)
	{
		return await this.PostSuccessAsync($"/roles/{roleId}/permissions", permissions);
	}

	public async Task<bool> AddRoleToGroup(Role role, string groupName)
	{
		var groupUrlStub = WebUtility.UrlEncode(groupName);
		return await this.PostSuccessAsync($"/groups/{groupUrlStub}/roles", role);
	}

	public async Task<bool> AddUser(UserApiModel user)
	{
		return await this.PostSuccessAsync("/user", user);
	}

	public async Task<object> GetGroupByName(string groupName)
	{
		var groupUrlStub = WebUtility.UrlEncode(groupName);
		return await this.GetAsync($"/groups/{groupUrlStub}/roles");
	}

	public async Task<object> GetGroupsForUser(string identityProvider, string subjectId)
	{
		var identityProviderStub = WebUtility.UrlEncode(identityProvider);
		var subjectIdStub = WebUtility.UrlEncode(subjectId);
		return await this.GetAsync($"/user/{identityProviderStub}/{subjectIdStub}/groups");
	}

	public async Task<UserPermissions> GetPermissionsForUser(string grain = null, string securableItem = null)
	{
		var queryString = string.Empty;
		if (!string.IsNullOrEmpty(grain) && !string.IsNullOrEmpty(securableItem))
		{
			queryString = $"?grain={grain}&securableItem={securableItem}";
		}
		return await this.GetAsync<UserPermissions>($"/user/permissions{queryString}");
	}

	public async Task<object> AddUserToRole(string identityProvider, string subjectId, Role[] roles)
	{
		var identityProviderStub = WebUtility.UrlEncode(identityProvider);
		var subjectIdStub = WebUtility.UrlEncode(subjectId);
		var url = $"/user/{identityProviderStub}/{subjectIdStub}/roles";
		return await this.PostAsync(url, roles);
	}

	public async Task<object> GetUserRoles(string identityProvider, string subjectId)
	{
		var identityProviderStub = WebUtility.UrlEncode(identityProvider);
		var subjectIdStub = WebUtility.UrlEncode(subjectId);
		var url = $"/user/{identityProviderStub}/{subjectIdStub}/roles";
		return await this.GetAsync(url);
	}

	public async Task<object> GetUser(string identityProvider, string subjectId)
	{
		var identityProviderStub = WebUtility.UrlEncode(identityProvider);
		var subjectIdStub = WebUtility.UrlEncode(subjectId);
		var url = $"/user/{identityProviderStub}/{subjectIdStub}";
		return await this.GetAsync(url);
	}

	public async Task<Client> PostClient(Client client)
	{
		return await this.PostAsync<Client>($"/clients", client);
	}

	public async Task<List<Role>> GetMemberRoles(string subjectId, string identityProvider)
	{
		var subjectIdStub = WebUtility.UrlEncode(subjectId);
		var identityProviderStub = WebUtility.UrlEncode(identityProvider);
		return await this.GetAsync<List<Role>>($"/user/{identityProviderStub}/{subjectIdStub}/roles");
	}

	public class UserPermissions
	{
		public IEnumerable<string> Permissions { get; set; }
		public string RequestedGrain { get; set; }
		public string RequestedSecurableItem { get; set; }
	}

	public class Permission
	{
		public string Id { get; set; }

		public string Grain { get; set; }

		public string SecurableItem { get; set; }

		public string Name { get; set; }
	}

	public class Role
	{
		public string Id { get; set; }
		public string Grain { get; set; }
		public string SecurableItem { get; set; }
		public string Name { get; set; }
		public object ParentRole { get; set; }
		public List<object> Permissions { get; set; }
		public List<object> DeniedPermissions { get; set; }
		public List<object> ChildRoles { get; set; }
	}

	public class UserApiModel
	{
		public string SubjectId { get; set; }

		public string IdentityProvider { get; set; }

		//public IEnumerable<string> Groups { get; set; }

		//public ICollection<RoleApiModel> Roles { get; set; }
	}

	private static AuthorizationApiItem ParseAuthorizationItem(string item)
	{
		var parts = item.Split('/');
		if (parts.Length != 2) throw new ArgumentException("string parameter must be in the format grain/app.name");
		var subparts = parts[1].Split('.');
		if (parts.Length != 2) throw new ArgumentException("string parameter must be in the format grain/app.name");
		return new AuthorizationApiItem
		{
			Grain = parts[0],
			SecurableItem = subparts[0],
			Name = subparts[1]
		};
	}

	public class AuthorizationApiItem
	{
		public string Grain { get; set; }
		public string SecurableItem { get; set; }
		public string Name { get; set; }
	}

	public class Client
	{
		public string Id { get; set; }
		public string Name { get; set; }
	}
}

public class TerminologyClient : FabricClient
{
	private const string Scope = "fabric/authorization.read";
	public TerminologyClient(DiscoveryClient discoveryClient) : base(discoveryClient, DosService.TerminologyService, Scope)
	{
	}

	public async Task<object> GetValueSetCodes()
	{
		return await this.GetAsync($"/valuesetcodes");
	}
}

public abstract class FabricClient : IDisposable
{
	private readonly DiscoveryClient discoveryClient;
	
	private readonly string scope;
	
	private const string clientId = "fabric-installer";
	
	private DosService service;
	
	private Uri _baseUri;

	protected HttpClient HttpClient { private set; get; }

	public FabricClient(DiscoveryClient discoveryClient, DosService service, string scope)
	{
		this.discoveryClient = discoveryClient;
		this.scope = scope;
		this.service = service;
	}

	protected async Task SetClient()
	{
		if (this.HttpClient == null)
		{
			this.HttpClient = await CustomHttpClientFactory.GetTokenAndCreateClient(this.discoveryClient, clientId, this.scope);
		}
	}
	
	public async Task<Uri> GetBaseUri()
	{
		if (this._baseUri != null)
		{
			return this._baseUri;
		}
		
		this._baseUri = await this.discoveryClient.GetService(this.service);
		return _baseUri;
	}

	protected async Task<string> GetAsync(string url, Dictionary<string, string> parameters = null)
	{
		await this.SetClient();
		if (parameters != null)
		{
			foreach (var keyValue in parameters)
			{

			}
		}
		var baseUri = await GetBaseUri();
		var fullUri = Combine(baseUri, url);
		var response = await HttpClient.GetAsync(fullUri);
		await response.CustomEnsureSuccessStatusCode(fullUri);
		var json = await response.Content.ReadAsStringAsync();
		return JValue.Parse(json).ToString(Newtonsoft.Json.Formatting.Indented);
	}

	protected async Task<T> GetAsync<T>(string url, Dictionary<string, string> parameters = null)
	{
		await this.SetClient();
		if (parameters != null)
		{
			foreach (var keyValue in parameters)
			{

			}
		}
		var baseUri = await GetBaseUri();
		var fullUri = Combine(baseUri, url);
		var response = await HttpClient.GetAsync(fullUri);
		await response.CustomEnsureSuccessStatusCode(fullUri);
		return await response.Content.ReadAsAsync<T>();
	}

	protected async Task<object> PostAsync(string url, object postObject)
	{
		await SetClient();
		var baseUri = await GetBaseUri();
		var fullUri = Combine(baseUri, url);
		var response = await HttpClient.PostAsync(fullUri, CreateJsonContent(postObject));
		await response.CustomEnsureSuccessStatusCode(fullUri, JsonConvert.SerializeObject(postObject));
		return JsonConvert.DeserializeObject(await response.Content.ReadAsStringAsync());
	}

	protected async Task<T> PostAsync<T>(string url, T postObject)
	{
		await SetClient();
		var baseUri = await GetBaseUri();
		var fullUri = Combine(baseUri, url);
		var response = await HttpClient.PostAsync(fullUri, CreateJsonContent(postObject));
		await response.CustomEnsureSuccessStatusCode(fullUri, JsonConvert.SerializeObject(postObject));
		return await response.Content.ReadAsAsync<T>();
	}

	protected async Task<T> PutAsync<T>(string url, T putObject)
	{
		await SetClient();
		var baseUri = await GetBaseUri();
		var fullUri = Combine(baseUri, url);
		var response = await HttpClient.PutAsync(fullUri, CreateJsonContent(putObject));
		await response.CustomEnsureSuccessStatusCode(fullUri, JsonConvert.SerializeObject(putObject));
		return await response.Content.ReadAsAsync<T>();
	}

	protected async Task<bool> PostSuccessAsync<T>(string url, T postObject)
	{
		await SetClient();
		var baseUri = await GetBaseUri();
		var fullUri = Combine(baseUri, url);
		var response = await HttpClient.PostAsync(fullUri, CreateJsonContent(postObject));
		await response.CustomEnsureSuccessStatusCode(url, JsonConvert.SerializeObject(postObject));
		return response.IsSuccessStatusCode;
	}

	protected async Task<bool> DeleteAsync(string url)
	{
		await SetClient();
		var baseUri = await GetBaseUri();
		var fullUri = Combine(baseUri, url);
		var response = await HttpClient.DeleteAsync(fullUri);
		await response.CustomEnsureSuccessStatusCode(fullUri);
		return response.IsSuccessStatusCode;
	}

	private StringContent CreateJsonContent(object model)
	{
		return new StringContent(JsonConvert.SerializeObject(model), Encoding.UTF8, "application/json");
	}

	public void Dispose()
	{
		Dispose(true);
		GC.SuppressFinalize(this);
	}

	~FabricClient()
	{
		Dispose(false);
	}

	protected virtual void Dispose(bool disposing)
	{
		if (disposing && HttpClient != null)
		{
			HttpClient.Dispose();
			HttpClient = null;
		}
	}

	private static string Combine(Uri uri1, string uri2)
	{
		if (uri1 == null)
		{
			throw new ArgumentNullException(nameof(uri1));
		}

		if (uri2 == null)
		{
			throw new ArgumentNullException(nameof(uri2));
		}

		return string.Format($"{uri1.ToString().TrimEnd('/')}/{uri2.TrimStart('/')}", uri1, uri2);
	}
}

public static class CustomHttpClientFactory
{
	public static async Task<HttpClient> GetTokenAndCreateClient(DiscoveryClient discoveryClient, string clientId, string scope)
	{
		var fabricSecret = GetFabricInstallerSecret();
		var authorization = await discoveryClient.GetService(DosService.IdentityService);
		string accessToken = await GetToken(authorization, clientId, fabricSecret, scope);
		return CreateClient(accessToken);
	}
	
	public static HttpClient CreateClient(string accessToken)
	{
		var accessTokenClient = CreateHttpClient();
		accessTokenClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
		accessTokenClient.DefaultRequestHeaders.Add("correlation-token", Guid.NewGuid().ToString());
		accessTokenClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
		return accessTokenClient;
	}
	
	public static HttpClient CreateClient()
	{
		return CreateHttpClient();
	}

	public static string GetFabricInstallerSecret()
	{
		var installConfig = Path.Combine(Environment.ExpandEnvironmentVariables("%ProgramW6432%"), "Health Catalyst", "install.config");
		if (!File.Exists(installConfig))
		{
			throw new InvalidOperationException($"install config does not exist at '{installConfig}'. Please install DOS");
		}
		
		XmlDocument doc = new XmlDocument();
		doc.Load(installConfig);
		XmlNode root = doc.DocumentElement;
		
		var fabricInstallerSecret = root.SelectNodes("/installation/settings/scope[@name='common']/variable[@name='fabricInstallerSecret']/@value")[0].Value;
		var encryptionCertificateThumbprint = root.SelectNodes("/installation/settings/scope[@name='common']/variable[@name='encryptionCertificateThumbprint']/@value")[0].Value;
		
		if (string.IsNullOrWhiteSpace(fabricInstallerSecret))
		{
			throw new InvalidOperationException($"fabricInstallerSecret not found in {installConfig}");
		}

		if (string.IsNullOrWhiteSpace(encryptionCertificateThumbprint))
		{
			throw new InvalidOperationException($"encryptionCertificateThumbprint not found in {installConfig}");
		}

		var decryptedSecret = EncryptionUtility.DecryptString(fabricInstallerSecret, encryptionCertificateThumbprint);
		return decryptedSecret;
	}

	private static async Task<string> GetToken(Uri tokenUri, string clientId, string secret, string scope)
	{
		Uri tokenEndpoint = new Uri($"{tokenUri.ToString().TrimEnd('/')}/connect/token");

		using (var tokenClient = CreateHttpClient())
		{
			var dict = new Dictionary<string, string>();
			dict.Add("client_secret", secret);
			dict.Add("client_id", clientId);
			dict.Add("grant_type", "client_credentials");
			dict.Add("scope", scope);
			using (var content = new FormUrlEncodedContent(dict))
			{
				content.Headers.Clear();
				content.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
				HttpResponseMessage tokenResponse = await tokenClient.PostAsync(tokenEndpoint, content);
				await tokenResponse.CustomEnsureSuccessStatusCode(tokenEndpoint.ToString(), "failed to get access token");
				if (!tokenResponse.IsSuccessStatusCode)
				{
					throw new AuthenticationException($"Could not get token for: {tokenEndpoint}. Reason: {(int)tokenResponse.StatusCode} - {tokenResponse.ReasonPhrase}");
				}

				var accessToken = await tokenResponse.Content.ReadAsAsync<AccessToken>();
				return accessToken.access_token;
			}
		}
	}

	static private HttpClient CreateHttpClient()
	{
		var defaultHandler = new HttpClientHandler() { UseDefaultCredentials = true };
		var client = HttpClientFactory.Create(defaultHandler);
		return client;
	}

	public static async Task CustomEnsureSuccessStatusCode(this HttpResponseMessage response, string url, string additionalInfo = null)
	{
		if (!response.IsSuccessStatusCode)
		{
			if ((int)response.StatusCode == 409)
			{
				$"409 CONFLICT for request {url} for object {additionalInfo}".Dump("409 CONFLICT");
			}
			else if ((int)response.StatusCode == 401 && response.Headers.Any(header => header.Key == "WWW-Authenticate" && header.Value.Any(value => value == "NTLM")))
			{
				throw new HttpRequestException($"Failed Windows Authentication for request {url}: {(int)response.StatusCode} - {response.ReasonPhrase}");
			}
			else
			{
				string error;
				var json = await response.Content.ReadAsStringAsync();
				CustomHttpClientFactory.ErrorReason reason = null;
				try
				{
					reason = JsonConvert.DeserializeObject<CustomHttpClientFactory.ErrorReason>(json);
				}
				catch (JsonReaderException)
				{
					// do nothing, its not a standard error
				}

				if (reason != null && !string.IsNullOrWhiteSpace(reason.message))
				{
					error = $"Request Failed for request {url}: {reason.code} - {reason.message}";
					reason.Dump(error);
				}
				else
				{
					error = $"Request Failed for request {url}: {(int)response.StatusCode} - {response.ReasonPhrase} - {json}";
					response.Dump(error);
				}

				if (!string.IsNullOrWhiteSpace(additionalInfo))
				{
					additionalInfo.Dump("json");
				}

				throw new FabricException(error, response.StatusCode.ToString(), additionalInfo);
			}
		}
	}

	public static string AttachParameters(Dictionary<string, string> parameters)
	{
		if (parameters.Count == 0)
		{
			return string.Empty;
		}

		var stringBuilder = new StringBuilder();
		string str = "?";
		foreach (var keyvalue in parameters)
		{
			stringBuilder.Append(str + WebUtility.UrlEncode(keyvalue.Key) + "=" + WebUtility.UrlEncode(keyvalue.Value));
			str = "&";
		}
		stringBuilder.Length--;
		return stringBuilder.ToString();
	}

	public class AccessToken
	{
		public string access_token { get; set; }
		public int expires_in { get; set; }
		public string token_type { get; set; }
	}

	public class ErrorReason
	{
		public string code { get; set; }
		public string message { get; set; }
		public string target { get; set; }
		public object details { get; set; }
		public object innerError { get; set; }
	}

	public class FabricException : Exception
	{
		public string statusCode;
		public string additionalInfo;

		public FabricException(string message, string statusCode, string additionalInfo) : base(message)
		{
			this.statusCode = statusCode;
			this.additionalInfo = additionalInfo;
		}
	}
}

public static class EncryptionUtility
{
	public static string DecryptString(string encryptedString, string thumbPrint)
	{
		if (string.IsNullOrEmpty(encryptedString) || string.IsNullOrEmpty(thumbPrint))
		{
			throw new ArgumentException("encryptedString and thumbPrint are required");
		}
		if (!encryptedString.Contains("!!enc!!:"))
		{
			return encryptedString;// not encrypted, send it back
		}
		
		var certs = EnumCertificates(StoreName.My, StoreLocation.LocalMachine).Cast< System.Security.Cryptography.X509Certificates.X509Certificate2 >();
		var targetCert = certs.FirstOrDefault(x => x.Thumbprint == thumbPrint);
		if (targetCert == null)
		{
			throw new InvalidOperationException($"Certificate with thumbprint {thumbPrint} does not exist");
		}
		
		var rsaObj = (RSACryptoServiceProvider)targetCert.PrivateKey;
		var cleaned = encryptedString.Replace("!!enc!!:", string.Empty);
		var base64 = Convert.FromBase64String(cleaned);
		var decryptedByes = rsaObj.Decrypt(base64, true);
		var decryptedString = UTF8Encoding.UTF8.GetString(decryptedByes);
		return decryptedString;
	}

	private static void PrintCertificateInfo(X509Certificate2 certificate, int index)
	{
		(new
		{
			certificate.FriendlyName,
			Issuer = certificate.IssuerName.Name,
			SubjectName = certificate.SubjectName.Name,
			certificate.NotBefore,
			certificate.NotAfter,
			certificate.SerialNumber,
			SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName,
			certificate.Thumbprint
		}).Dump(index.ToString());
	}

	private static X509Certificate2Collection EnumCertificates(StoreName name, StoreLocation location)
	{
		X509Store store = new X509Store(name, location);
		try
		{
			store.Open(OpenFlags.ReadOnly);
			//int i = 1;
			var certs = store.Certificates;
			//foreach (X509Certificate2 certificate in certs)
			//{
			//	PrintCertificateInfo(certificate, i++);
			//}
			return certs;
		}
		finally
		{
			store.Close();
		}
	}
}

#region samples

/* ************************ GET CLIENT ************************

using (var manageClient = new ManageClients(identityServer, identityServer, issuingClientId, clientSecret))
{
	var client = await manageClient.GetClient("dos");
	client.Dump("dos");
}

*/

/* ************************ UPDATE ACCESS TOKEN EXPIRATION ************************

using (var manageClient = new ManageClients(identityServer, identityServer, issuingClientId, clientSecret))	
{
	var client = await manageClient.GetClient("atlas-test");
	client.Dump("old");

	client.accessTokenLifetime = 120;
	
	var updated = await manageClient.PutClient(client);
	updated.Dump("updated");
}
*/


/************************ DUPLICATE CLIENT ************************

using (var manageClient = new ManageClients(identityServer, identityServer, issuingClientId, clientSecret))	
{
	var client = await manageClient.GetClient("atlas");
	client.Dump("old");

	client.clientName = client.clientId = "atlas2";
	
	var updated = await manageClient.PostClient(client);
	updated.Dump("updated");
}

*/

/************************* CREATE PERMISSIONS ************************

using (var authClient = new AuthorizationClient(authorizationServer, identityServer, issuingClientId, clientSecret))
	{
		var permissions = new[] {
				"readall",
				"entitiesreadall",
				"create",
				"update",
				"delete",
				"entitiescreate",
				"entitiesupdate",
				"entitiesdelete",
				"jobsexecute",
				"systemattributesread",
				"systemattributescreate",
				"systemattributesupdate",
				"systemattributesdelete",
				"auditlogread",
				"readvisible",
				"entitiesreadpublic",
				"jobsexecute"};

		foreach (var permission in permissions)
		{
			var p = new AuthorizationClient.Permission
			{
				Grain = "dos",
				Name = permission,
				SecurableItem = "datamarts"
			};
			var a = await authClient.CreatePermission(p);
			a.Dump();
		}
	}

*/

/************************** CREATE ROLES ************************

using (var authClient = new AuthorizationClient(authorizationServer, identityServer, issuingClientId, clientSecret))
	{
		var roles = new[] {
				"dosadmin",
				"DataMartContributor",
				"DataMartReader",
				"DataMartPublicEntityReader",
				"DataMartOperator"};

		foreach (var role in roles)
		{
			var newRole = new AuthorizationClient.Role
			{
				Grain = "dos",
				Name = role,
				SecurableItem = "datamarts"
			};
			var resp = await authClient.CreateRole(newRole);
			resp.Dump();
		}
	}
*/

/***************************** ALL OF IT ****************************

using (var authClient = new AuthorizationClient(authorizationServer, identityServer, issuingClientId, clientSecret))
	{
		
		const string dosGrain = "dos";
		const string datamartSecurableItem = "datamarts";

		// DELETES ALL permissions and roles from "dos" grain and "datamarts" securable item scope 
		//var deleteRoles = await authClient.GetRoles(dosGrain, datamartSecurableItem);
		//foreach (var role in deleteRoles)
		//{
		//	await authClient.DeleteRole(role.Id);
		//	$"deleted role: {role.Name}".Dump();
		//}

		//var deletePermissions = await authClient.GetPermissions(dosGrain, datamartSecurableItem);
		//foreach (var permission in deletePermissions)
		//{
		//	await authClient.DeletePermission(permission.Id);
		//	$"deleted permission: {permission.Name}".Dump();
		//}

		var roles = new[]
			{
				new {
					Name = "dosadmin",
					Permissions = new []
					{
						"readall",
						"entitiesreadall",
						"create",
						"update",
						"delete",
						"entitiescreate",
						"entitiesupdate",
						"entitiesdelete",
						"jobsexecute",
						"systemattributesread",
						"systemattributescreate",
						"systemattributesupdate",
						"systemattributesdelete",
						"auditlogread",
						"notesdelete"
					}
				},
				new
				{
					Name = "DataMartContributor",
					Permissions = new []
					{
						"readall",
						"entitiesreadall",
						"create",
						"update",
						"delete",
						"entitiescreate",
						"entitiesupdate",
						"entitiesdelete",
						"systemattributesread",
						"auditlogread",
					}
				},
				new
				{
					Name = "DataMartReader",
					Permissions = new []
					{
						"readvisible",
						"entitiesreadall",
						"auditlogread",
						}
				},
				new
				{
					Name = "DataMartPublicEntityReader",
					Permissions = new []
					{
						"readvisible",
						"entitiesreadpublic",
						"auditlogread",
					}
				},
				new
				{
					Name = "DataMartOperator",
					Permissions = new []
					{
						"jobsexecute"
					}
				}
			};

		foreach (var permission in roles.SelectMany(perm => perm.Permissions).Distinct())
		{
			var newPermission = new AuthorizationClient.Permission
			{
				Grain = dosGrain,
				Name = permission,
				SecurableItem = datamartSecurableItem
			};
			var dbPermission = await authClient.CreatePermission(newPermission);
			$"created new permission: {newPermission.Name}".Dump();
		}

		foreach (var role in roles)
		{
			var newRole = new AuthorizationClient.Role
			{
				Grain = dosGrain,
				Name = role.Name,
				SecurableItem = datamartSecurableItem
			};
			var dbRole = await authClient.CreateRole(newRole);
			$"created new role: {newRole.Name}".Dump();
		}

		var dbPermissions = await authClient.GetPermissions(dosGrain, datamartSecurableItem);
		var dbRoles = await authClient.GetRoles(dosGrain, datamartSecurableItem);

		foreach (var role in dbRoles)
		{
			var targetRole = roles.FirstOrDefault(r => r.Name == role.Name);

			if (targetRole == null || role.Permissions.Count > 0)
			{
				$"Skipping {role.Name} permissions already setup".Dump();
				continue;
			}

			var newPermissions = targetRole.Permissions.Select(p =>
			new AuthorizationClient.Permission
			{
				Id = dbPermissions.First(perm => perm.Name == p).Id,
				Grain = dosGrain,
				SecurableItem = datamartSecurableItem,
				Name = p
			}).ToArray();

			var resp = await authClient.AddPermissionToRole(newPermissions, role.Id);
			$"Associated {role.Name} to permissions: {string.Join(", ", newPermissions.Select(p => p.Name))}".Dump();
		}
	}
*/


/************************ fabric-accesscontrol CLIENT ************************

using (var manageClient = new ManageClients(identityServer, identityServer, issuingClientId, clientSecret))	
{
	var newClient = JsonConvert.DeserializeObject< ManageClients.Client>(@"{
""enabled"": true,
""clientId"": ""fabric-accesscontrol"",
""clientSecret"": null,
""requireClientSecret"": true,
""allowedGrantTypes"": [
""implicit""
],
""requirePkce"": false,
""allowPlainTextPkce"": false,
""redirectUris"": [
""http://localhost:4200/oidc-callback.html"",
""https://fabricservices.hqcatalyst.local/angular/oidc-callback.html"",
""https://fabricservices.hqcatalyst.local/angular/silent.html""
],
""allowedScopes"": [
""openid"",
""profile"",
""fabric.profile"",
""fabric/authorization.read"",
""fabric/authorization.write"",
""fabric/authorization.manageclients"",
""patientapi"",
""fabric/identity.manageresources"",
""fabric/identity.read"",
""dos"",
""dos.metadata"",
""fabric/idprovider.searchusers""
],
""allowOfflineAccess"": false,
""allowAccessTokensViaBrowser"": true,
""protocolType"": ""oidc"",
""postLogoutRedirectUris"": [
""https://fabricservices.hqcatalyst.local/angular""
],
""enableLocalLogin"": true,
""identityProviderRestrictions"": [],
""logoutUri"": null,
""logoutSessionRequired"": true,
""identityTokenLifetime"": 300,
""accessTokenLifetime"": 3600,
""authorizationCodeLifetime"": 300,
""absoluteRefreshTokenLifetime"": 2592000,
""slidingRefreshTokenLifetime"": 1296000,
""refreshTokenUsage"": 1,
""refreshTokenExpiration"": 1,
""updateAccessTokenClaimsOnRefresh"": false,
""accessTokenType"": 0,
""includeJwtId"": false,
""allowedCorsOrigins"": [
""https://fabricservices.hqcatalyst.local/angular"",
""http://localhost:4200""
],
""claims"": [],
""alwaysSendClientClaims"": false,
""alwaysIncludeUserClaimsInIdToken"": false,
""prefixClientClaims"": true,
""requireConsent"": false,
""allowRememberConsent"": true,
""clientName"": ""Fabric Access Control"",
""clientUri"": null,
""logoUri"": null
}");
	var client = await manageClient.PostClient(newClient);
	//var client = await manageClient.GetClient("fabric-accesscontrol");
	
	JsonConvert.SerializeObject(client, Newtonsoft.Json.Formatting.Indented).Dump();
}
*/
/************************* add atlas access to new server ************************

using (var manageClient = new ManageClients(identityServer, identityServer, issuingClientId, clientSecret))
{
	var client = await manageClient.GetClient("atlas");
	client.Dump("old");
	
	string atlasUri = "http://localhost/AtlasDev";

	client.allowedCorsOrigins.Add(atlasUri);

	client.redirectUris.Add(atlasUri);
	client.redirectUris.Add($"{atlasUri}/client/auth.html");
	client.redirectUris.Add($"{atlasUri}/client/silent.html");

	client.postLogoutRedirectUris.Add($"{atlasUri}/client/logout");
	client.postLogoutRedirectUris.Add(atlasUri);

	var updated = await manageClient.PutClient(client);
	updated.Dump("null means success!");

	updated = await manageClient.GetClient("atlas");
	updated.Dump("new");
}

*/


/************************* add user to role (doesn't work) ************************

using (var authClient = new AuthorizationClient(authorizationServer, identityServer, issuingClientId, clientSecret))
	{
		const string dosGrain = "dos";
		const string datamartSecurableItem = "datamarts";
		
		//var rolesToAdd = new [] { new AuthorizationClient.Role{ Grain = dosGrain, SecurableItem = datamartSecurableItem, Name = "dosadmin"}};
		var rolesToAdd = await authClient.GetRoles(dosGrain, datamartSecurableItem, "dosadmin");
		var r = await authClient.AddUserToRole("windows", @"HQCATALYST\\ben.anderson", rolesToAdd.ToArray());
		r.Dump();
	}
	
*/

/************************* copy client from identity to auth ************************

using (var manageClient = new ManageClients(identityServer, identityServer, issuingClientId, clientSecret))
	using (var authClient = new AuthorizationClient(authorizationServer, identityServer, issuingClientId, clientSecret))
	{
		var client = await manageClient.GetClient("fabric-accesscontrol");
		JsonConvert.SerializeObject(client, Newtonsoft.Json.Formatting.Indented).Dump("old");
		var postClient = new AuthorizationClient.Client 
		{
			Id = client.clientId,
			Name = client.clientName
		};
		var newClient = await authClient.PostClient(postClient);
		JsonConvert.SerializeObject(newClient, Newtonsoft.Json.Formatting.Indented).Dump("new");
	}

*/

/************************ get member roles ****************************

using (var authClient = new AuthorizationClient(authorizationServer, identityServer, issuingClientId, clientSecret))
{
	var roles = await authClient.GetMemberRoles(@"hqcatalyst\ben.anderson", "windows");
	roles.Dump();
}

*/

/************************** add user ****************************


using (var authClient = new AuthorizationClient(authorizationServer, identityServer, issuingClientId, clientSecret))
	{
		var user = new AuthorizationClient.UserApiModel { IdentityProvider = "windows", SubjectId = "not valid"};
		
		await authClient.AddUser(user);
	}
*/
#endregion
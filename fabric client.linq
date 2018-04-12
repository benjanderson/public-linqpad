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

	Uri identityServer = new Uri("https://atlasdemo.hqcatalyst.local/Identity");
	Uri authorizationServer = new Uri("https://atlasdemo.hqcatalyst.local/authorization");
	//Uri identityServer = new Uri("http://localhost/identity/v1");
	//Uri identityServer = new Uri("https://fabricservices.hqcatalyst.local/identity2");
	//Uri authorizationServer = new Uri("https://fabricservices.hqcatalyst.local/authorization2");
	//Uri authorizationServer = new Uri("http://localhost/authorization");


	string issuingClientId = "fabric-installer";

	string clientSecret = Util.GetPassword(identityServer + " client:" + issuingClientId);

	using (var authClient = new AuthorizationClient(authorizationServer, identityServer, issuingClientId, clientSecret))
	{
		var roles = await authClient.GetMemberRoles(@"hqcatalyst\ben.anderson", "windows");
		roles.Dump();
	}
}

public class ManageClients : FabricClient
{
	private const string Scope = "fabric/identity.manageresources";

	public ManageClients(Uri identityUri, Uri TokenUri, string clientId, string clientSecret) : base(identityUri, TokenUri, clientId, clientSecret, Scope)
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

	public AuthorizationClient(Uri authorizationUri, Uri TokenUri, string clientId, string clientSecret) : base(authorizationUri, TokenUri, clientId, clientSecret, Scope)
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

	public async Task<object> GetGroupByName(string groupName)
	{
		var groupUrlStub = WebUtility.UrlEncode(groupName);
		return await this.GetAsync($"/groups/{groupUrlStub}/roles");
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

public abstract class FabricClient : IDisposable
{
	private readonly Uri tokenUri;
	private readonly Uri baseUri;
	private readonly string clientSecret;
	private readonly string scope;
	private readonly string clientId;

	protected HttpClient HttpClient { private set; get; }

	public FabricClient(Uri baseUri, Uri TokenUri, string clientId, string clientSecret, string scope)
	{
		this.baseUri = baseUri;
		this.tokenUri = TokenUri;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.scope = scope;
	}

	protected async Task SetClient()
	{
		if (this.HttpClient == null)
		{
			this.HttpClient = await CustomHttpClientFactory.GetTokenAndCreateClient(this.tokenUri, this.clientId, this.clientSecret, this.scope);
		}
	}

	protected async Task<object> GetAsync(string url, Dictionary<string, string> parameters = null)
	{
		await this.SetClient();
		if (parameters != null)
		{
			foreach (var keyValue in parameters)
			{

			}
		}
		var response = await HttpClient.GetAsync(Combine(this.baseUri, url));
		await response.CustomEnsureSuccessStatusCode(url);
		var json = await response.Content.ReadAsStringAsync();
		return JsonConvert.DeserializeObject<object>(json);
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
		var response = await HttpClient.GetAsync(Combine(this.baseUri, url));
		await response.CustomEnsureSuccessStatusCode(url);
		return await response.Content.ReadAsAsync<T>();
	}

	protected async Task<object> PostAsync(string url, object postObject)
	{
		await SetClient();
		var response = await HttpClient.PostAsync(Combine(this.baseUri, url), CreateJsonContent(postObject));
		await response.CustomEnsureSuccessStatusCode(url, JsonConvert.SerializeObject(postObject));
		return JsonConvert.DeserializeObject(await response.Content.ReadAsStringAsync());
	}

	protected async Task<T> PostAsync<T>(string url, T postObject)
	{
		await SetClient();
		var response = await HttpClient.PostAsync(Combine(this.baseUri, url), CreateJsonContent(postObject));
		await response.CustomEnsureSuccessStatusCode(url, JsonConvert.SerializeObject(postObject));
		return await response.Content.ReadAsAsync<T>();
	}

	protected async Task<T> PutAsync<T>(string url, T putObject)
	{
		await SetClient();
		var response = await HttpClient.PutAsync(Combine(this.baseUri, url), CreateJsonContent(putObject));
		await response.CustomEnsureSuccessStatusCode(url, JsonConvert.SerializeObject(putObject));
		return await response.Content.ReadAsAsync<T>();
	}

	protected async Task<bool> PostSuccessAsync<T>(string url, T postObject)
	{
		await SetClient();
		var response = await HttpClient.PostAsync(Combine(this.baseUri, url), CreateJsonContent(postObject));
		await response.CustomEnsureSuccessStatusCode(url, JsonConvert.SerializeObject(postObject));
		return response.IsSuccessStatusCode;
	}

	protected async Task<bool> DeleteAsync(string url)
	{
		await SetClient();
		var response = await HttpClient.DeleteAsync(Combine(this.baseUri, url));
		await response.CustomEnsureSuccessStatusCode(url);
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
		if (uri2 == null)
		{
			throw new ArgumentNullException(nameof(uri2));
		}

		return string.Format($"{uri1.ToString().TrimEnd('/')}/{uri2.TrimStart('/')}", uri1, uri2);
	}
}

public static class CustomHttpClientFactory
{
	public static async Task<HttpClient> GetTokenAndCreateClient(Uri tokenUri, string clientId, string secret, string scope)
	{
		string accessToken = await GetToken(tokenUri, clientId, secret, scope);
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
				await tokenResponse.CustomEnsureSuccessStatusCode(tokenUri.ToString(), "failed to get access token");
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
				var reason = await response.Content.ReadAsAsync<CustomHttpClientFactory.ErrorReason>();
				if (reason != null)
				{
					error = $"Request Failed for request {url}: {reason.code} - {reason.message}";
					reason.Dump(error);
				}
				else
				{
					error = $"Request Failed for request {url}: {(int)response.StatusCode} - {response.ReasonPhrase}";
					response.Dump(error);
				}

				if (!string.IsNullOrWhiteSpace(additionalInfo))
				{
					additionalInfo.Dump("json");
				}

				throw new HttpRequestException(error);
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

	client.allowedCorsOrigins.Add("https://HC2252.hqcatalyst.local/Atlas");

	client.redirectUris.Add("https://HC2252.hqcatalyst.local/Atlas");
	client.redirectUris.Add("https://HC2252.hqcatalyst.local/Atlas/client/auth.html");
	client.redirectUris.Add("https://HC2252.hqcatalyst.local/Atlas/client/silent.html");

	client.postLogoutRedirectUris.Add("https://HC2252.hqcatalyst.local/Atlas/client/logout");
	client.postLogoutRedirectUris.Add("https://HC2252.hqcatalyst.local/Atlas");

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
#endregion
// Default URL for triggering event grid function in the local environment.
// http://localhost:7071/runtime/webhooks/EventGrid?functionName={functionname}

using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.Graph.Models;
using Microsoft.Graph;
using Microsoft.Graph.Applications.Item.AddPassword;
using Microsoft.Graph.Applications.Item.RemovePassword;

namespace AppRegSecretRotation
{
    public class RotateAppRegSecretFunction
    {
        private readonly ILogger _logger;

        public RotateAppRegSecretFunction(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<RotateAppRegSecretFunction>();
        }

        [Function(nameof(RotateAppRegSecretFunction))]
        public async Task Run([EventGridTrigger] KeyVaultSecretNearExpirationEvent input)
        {
            _logger.LogInformation(input.Data.ToString());

            _logger.LogInformation("Event Input Detail - Id: {Id} Topic: {Topic} Subject: {Subject} EventType: {EventType}", input.Id, input.Topic, input.Subject, input.EventType);

            var appRegistrationObjectId = input.Subject;
            
            var keyVaultUri = Environment.GetEnvironmentVariable("KEY_VAULT_URI");

            var secretClient = new SecretClient(new Uri(keyVaultUri), new DefaultAzureCredential());

            var previousClientSecret = await secretClient.GetSecretAsync(appRegistrationObjectId);

            var previousClientSecretKeyId = new Guid(previousClientSecret.Value.Properties.ContentType);

            _logger.LogInformation("Previous secret for app registration: {AppRegistrationObjectId} - Secret ID: {SecretId}", appRegistrationObjectId, previousClientSecretKeyId);

            var newPasswordCredential = await SetAppRegistrationClientSecret(appRegistrationObjectId, previousClientSecretKeyId);

            var newSecret = new KeyVaultSecret(appRegistrationObjectId, newPasswordCredential.SecretText)
                {
                    Properties =
                    {
                        ContentType = newPasswordCredential.KeyId.ToString(),
                        ExpiresOn = newPasswordCredential.EndDateTime
                    }
                };

            try
            {
                _logger.LogInformation("Setting new secret for app registration: {AppRegistrationObjectId}", appRegistrationObjectId);
                await secretClient.SetSecretAsync(newSecret);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error setting new secret for app registration: {AppRegistrationObjectId}", appRegistrationObjectId);
            }
        }

        private async Task<PasswordCredential> SetAppRegistrationClientSecret(
            string appRegistrationObjectId,
            Guid previousClientSecretKeyId)
        {
            var managedIdentityClientId = Environment.GetEnvironmentVariable("AZURE_CLIENT_ID");
            var numberOfDaysUntilExpiry = Environment.GetEnvironmentVariable("NUMBER_OF_DAYS_UNTIL_EXPIRY") ?? "30";

            var defaultCredential = new DefaultAzureCredential();

            var graphServiceClient = new GraphServiceClient(
                defaultCredential, new[] { "https://graph.microsoft.com/.default" });

            var passwordCredential = new PasswordCredential
            {
                DisplayName = "Set via automation",
                EndDateTime = DateTimeOffset.Now.AddDays(long.Parse(numberOfDaysUntilExpiry))
            };

            try
            {
                _logger.LogInformation("Rotating client secret for app registration: " + appRegistrationObjectId);

                // call microsoft graph to get ad application by object id
                var adApplication = await graphServiceClient.Applications[appRegistrationObjectId]
                    .GetAsync();

                _logger.LogInformation("Found app registration: " + adApplication.DisplayName);

                await graphServiceClient.Applications[appRegistrationObjectId]
                    .AddPassword
                    .PostAsync(new AddPasswordPostRequestBody
                    {
                        PasswordCredential = passwordCredential
                    });

                // Remove the old client secret
                await graphServiceClient.Applications[appRegistrationObjectId]
                    .RemovePassword
                    .PostAsync(new RemovePasswordPostRequestBody
                    {
                        KeyId = previousClientSecretKeyId
                    });
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Error rotating client secret for app registration: " + appRegistrationObjectId);
                _logger.LogError(e.Message);
                return null;
            }

            return passwordCredential;
        }
    }

    public class KeyVaultSecretNearExpirationEvent
    {
        public string Id { get; set; }

        public string Topic { get; set; }

        public string Subject { get; set; }

        public string EventType { get; set; }

        public DateTime EventTime { get; set; }

        public object Data { get; set; }
    }
}

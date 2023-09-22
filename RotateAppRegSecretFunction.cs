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

namespace AppRegSecretRotation;

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
        _logger.LogInformation("Event Input Detail - Id: {Id} Topic: {Topic} Subject: {Subject} EventType: {EventType}", input.Id, input.Topic, input.Subject, input.EventType);

        var appRegistrationObjectId = input.Subject;
            
        var keyVaultUri = Environment.GetEnvironmentVariable("KEY_VAULT_URI");

        if (string.IsNullOrWhiteSpace(keyVaultUri))
        {
            _logger.LogError("KEY_VAULT_URI environment variable not set");
            return;
        }

        var secretClient = new SecretClient(new Uri(keyVaultUri), new DefaultAzureCredential());

        var previousClientSecret = await secretClient.GetSecretAsync(appRegistrationObjectId);

        var previousClientSecretKeyId = new Guid(previousClientSecret.Value.Properties.ContentType);

        _logger.LogInformation("Previous secret for app registration: {AppRegistrationObjectId} - Secret ID: {SecretId}", appRegistrationObjectId, previousClientSecretKeyId);

        var newPasswordCredential = await SetAppRegistrationClientSecret(appRegistrationObjectId, previousClientSecretKeyId);

        if (newPasswordCredential != null)
        {
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
    }

    private async Task<PasswordCredential?> SetAppRegistrationClientSecret(
        string appRegistrationObjectId,
        Guid previousClientSecretKeyId)
    {
        try
        {
            var numberOfDaysUntilExpiry = Environment.GetEnvironmentVariable("NUMBER_OF_DAYS_UNTIL_EXPIRY") ?? "31";

            var graphServiceClient = new GraphServiceClient(
                new DefaultAzureCredential(), new[] { "https://graph.microsoft.com/.default" });

            var initialPasswordCredential = new PasswordCredential
            {
                DisplayName = "set-via-automation",
                EndDateTime = DateTimeOffset.Now.AddDays(int.Parse(numberOfDaysUntilExpiry))
            };

            var adApplication = await graphServiceClient.Applications[appRegistrationObjectId]
                .GetAsync();

            if (adApplication is null)
            {
                _logger.LogError("App registration not found: {AppRegistrationObjectId}", appRegistrationObjectId);
                return null;
            }

            _logger.LogInformation("Rotating client secret for app registration: {AppRegistrationObjectId}", appRegistrationObjectId);

            var finalPasswordCredential = await graphServiceClient.Applications[appRegistrationObjectId]
                .AddPassword
                .PostAsync(new AddPasswordPostRequestBody
                {
                    PasswordCredential = initialPasswordCredential
                });

            await graphServiceClient.Applications[appRegistrationObjectId]
                .RemovePassword
                .PostAsync(new RemovePasswordPostRequestBody
                {
                    KeyId = previousClientSecretKeyId
                });

            return finalPasswordCredential;
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Error rotating client secret for app registration: {AppRegistrationObjectId}", appRegistrationObjectId);
        }

        return null;
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
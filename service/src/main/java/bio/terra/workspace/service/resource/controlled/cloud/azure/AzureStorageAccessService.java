package bio.terra.workspace.service.resource.controlled.cloud.azure;

import bio.terra.common.exception.ForbiddenException;
import bio.terra.common.iam.BearerToken;
import bio.terra.workspace.amalgam.landingzone.azure.LandingZoneApiDispatch;
import bio.terra.workspace.app.configuration.external.AzureConfiguration;
import bio.terra.workspace.app.configuration.external.FeatureConfiguration;
import bio.terra.workspace.generated.model.ApiAzureLandingZoneDeployedResource;
import bio.terra.workspace.service.crl.CrlService;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.iam.SamRethrow;
import bio.terra.workspace.service.iam.SamService;
import bio.terra.workspace.service.iam.model.SamConstants;
import bio.terra.workspace.service.resource.controlled.ControlledResourceMetadataManager;
import bio.terra.workspace.service.resource.controlled.cloud.azure.storage.StorageAccountKeyProvider;
import bio.terra.workspace.service.resource.controlled.cloud.azure.storageContainer.ControlledAzureStorageContainerResource;
import bio.terra.workspace.service.resource.model.WsmResourceType;
import bio.terra.workspace.service.workspace.AzureCloudContextService;
import com.azure.core.http.HttpClient;
import com.azure.resourcemanager.storage.models.StorageAccount;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobContainerClientBuilder;
import com.azure.storage.blob.sas.BlobContainerSasPermission;
import com.azure.storage.blob.sas.BlobServiceSasSignatureValues;
import com.azure.storage.common.StorageSharedKeyCredential;
import com.azure.storage.common.sas.SasIpRange;
import com.azure.storage.common.sas.SasProtocol;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Service for Azure storage access management.
 *
 * <p>Rather than providing direct access to Azure storage containers, storage access is
 * accomplished via the minting of shared access signatures (SAS).
 */
@Component
public class AzureStorageAccessService {
  private static final Logger logger = LoggerFactory.getLogger(AzureStorageAccessService.class);

  private final SamService samService;
  private final CrlService crlService;
  private final FeatureConfiguration features;
  private final StorageAccountKeyProvider storageAccountKeyProvider;
  private final ControlledResourceMetadataManager controlledResourceMetadataManager;
  private final LandingZoneApiDispatch landingZoneApiDispatch;
  private final AzureCloudContextService azureCloudContextService;
  private final AzureConfiguration azureConfiguration;

  @Autowired
  public AzureStorageAccessService(
      SamService samService,
      CrlService crlService,
      StorageAccountKeyProvider storageAccountKeyProvider,
      ControlledResourceMetadataManager controlledResourceMetadataManager,
      LandingZoneApiDispatch landingZoneApiDispatch,
      AzureCloudContextService azureCloudContextService,
      FeatureConfiguration features,
      AzureConfiguration azureConfiguration) {
    this.samService = samService;
    this.crlService = crlService;
    this.controlledResourceMetadataManager = controlledResourceMetadataManager;
    this.landingZoneApiDispatch = landingZoneApiDispatch;
    this.azureCloudContextService = azureCloudContextService;
    this.features = features;
    this.storageAccountKeyProvider = storageAccountKeyProvider;
    this.azureConfiguration = azureConfiguration;
  }

  private BlobContainerSasPermission getSasTokenPermissions(
      AuthenticatedUserRequest userRequest,
      UUID storageContainerUuid,
      String samResourceName,
      String desiredPermissions) {
    final List<String> containerActions =
        SamRethrow.onInterrupted(
            () ->
                samService.listResourceActions(
                    userRequest, samResourceName, storageContainerUuid.toString()),
            "listResourceActions");

    String possiblePermissions = "";
    for (String action : containerActions) {
      if (action.equals(SamConstants.SamControlledResourceActions.READ_ACTION)) {
        possiblePermissions += "rl";
      } else if (action.equals(SamConstants.SamControlledResourceActions.WRITE_ACTION)) {
        possiblePermissions += "acwd";
      }
    }

    if (possiblePermissions.isEmpty()) {
      throw new ForbiddenException(
          String.format(
              "User is not authorized to get a SAS token for container %s",
              storageContainerUuid.toString()));
    }

    // ensure the requested permissions, if present, are a subset of the max possible permissions
    String effectivePermissions;
    if (desiredPermissions != null) {
      var possiblePermissionsSet =
          SasPermissionsHelper.permissionStringToCharSet(possiblePermissions);
      var desiredPermissionsSet =
          SasPermissionsHelper.permissionStringToCharSet(desiredPermissions);

      if (!possiblePermissionsSet.containsAll(desiredPermissionsSet)) {
        throw new ForbiddenException("Not authorized");
      }
      effectivePermissions = desiredPermissions;
    } else {
      effectivePermissions = possiblePermissions;
    }

    return BlobContainerSasPermission.parse(effectivePermissions);
  }

  /**
   * Creates a SAS token with a default start and expiry (drawn from app-level config)
   *
   * @param workspaceUuid id of the workspace that owns the container resource
   * @param storageContainerResource storage container object we want to mint a SAS for
   * @param userRequest The authenticated user's request
   * @param sasIpRange (optional) IP address or range of IPs from which the Azure APIs will accept
   *     requests for the token being minted.
   * @return A bundle of 1) a full Azure SAS URL, including the storage account hostname and 2) the
   *     token query param fragment
   */
  public AzureSasBundle createAzureStorageContainerSasToken(
      UUID workspaceUuid,
      ControlledAzureStorageContainerResource storageContainerResource,
      AuthenticatedUserRequest userRequest,
      String sasIpRange,
      String sasBlobName,
      String sasPermissions) {

    OffsetDateTime startTime =
        OffsetDateTime.now().minusMinutes(azureConfiguration.getSasTokenStartTimeMinutesOffset());
    long secondDuration = azureConfiguration.getSasTokenExpiryTimeMinutesOffset() * 60;
    OffsetDateTime expiryTime = OffsetDateTime.now().plusSeconds(secondDuration);

    return createAzureStorageContainerSasToken(
        workspaceUuid,
        storageContainerResource.getResourceId(),
        userRequest,
        new SasTokenOptions(sasIpRange, startTime, expiryTime, sasBlobName, sasPermissions));
  }

  /**
   * Mints a new SAS for an Azure storage container. Access control is mediated by SAM and mapped to
   * Azure permissions.
   *
   * @param workspaceUuid id of the workspace that owns the container resource
   * @param storageContainerUuid id of the storage container resource
   * @param userRequest The authenticated user's request
   * @param sasTokenOptions Token options which include 1) ipRange - (optional) IP address or range
   *     of IPs from which the Azure APIs will accept requests for the token being minted. 2)
   *     startTime - Time at which the SAS will become functional 3) expiryTime - Time at which the
   *     SAS will expire 4) blobName - Requests access to a single blob in a container 5)
   *     permissions - Permissions associated with the SAS indicating what operations a client may
   *     perform on the resource
   * @return A bundle of 1) a full Azure SAS URL, including the storage account hostname and 2) the
   *     token query param fragment
   */
  public AzureSasBundle createAzureStorageContainerSasToken(
      UUID workspaceUuid,
      UUID storageContainerUuid,
      AuthenticatedUserRequest userRequest,
      SasTokenOptions sasTokenOptions) {
    features.azureEnabledCheck();

    logger.info(
        "user {} requesting SAS token for Azure storage container {} in workspace {}",
        userRequest.getEmail(),
        storageContainerUuid.toString(),
        workspaceUuid.toString());

    var storageData = getStorageAccountData(workspaceUuid, storageContainerUuid, userRequest);

    BlobContainerSasPermission blobContainerSasPermission =
        getSasTokenPermissions(
            userRequest,
            storageData.storageContainerResource().getResourceId(),
            storageData.storageContainerResource().getCategory().getSamResourceName(),
            sasTokenOptions.permissions());

    StorageSharedKeyCredential storageKey =
        storageAccountKeyProvider.getStorageAccountKey(
            workspaceUuid, storageData.storageAccountName());

    BlobContainerClient blobContainerClient =
        new BlobContainerClientBuilder()
            .credential(storageKey)
            .endpoint(storageData.endpoint())
            .httpClient(HttpClient.createDefault())
            .containerName(storageData.storageContainerResource().getStorageContainerName())
            .buildClient();
    BlobServiceSasSignatureValues sasValues =
        new BlobServiceSasSignatureValues(sasTokenOptions.expiryTime(), blobContainerSasPermission)
            .setStartTime(sasTokenOptions.startTime())
            .setProtocol(SasProtocol.HTTPS_ONLY);

    if (sasTokenOptions.ipRange() != null) {
      sasValues.setSasIpRange(SasIpRange.parse(sasTokenOptions.ipRange()));
    }

    String token;
    String resourceName;
    if (sasTokenOptions.blobName() != null) {
      var blobClient = blobContainerClient.getBlobClient(sasTokenOptions.blobName());
      token = blobClient.generateSas(sasValues);
      resourceName =
          storageData.storageContainerResource().getStorageContainerName()
              + "/"
              + sasTokenOptions.blobName();
    } else {
      token = blobContainerClient.generateSas(sasValues);
      resourceName = storageData.storageContainerResource().getStorageContainerName();
    }

    logger.info(
        "SAS token with expiry time of {} generated for user {} on container {} in workspace {}",
        sasTokenOptions.expiryTime(),
        userRequest.getEmail(),
        storageContainerUuid,
        workspaceUuid);

    return new AzureSasBundle(
        token,
        String.format(
            Locale.ROOT,
            "https://%s.blob.core.windows.net/%s?%s",
            storageData.storageAccountName(),
            resourceName,
            token));
  }

  /**
   * Returns an Azure container client suitable for interacting with a storage container and its
   * constiuent blobs.
   *
   * @param containerResource The WSM container resource the client will operate on
   * @param storageAccount The parent storage account for the WSM container resource
   * @return An Azure blob container client
   */
  public BlobContainerClient buildBlobContainerClient(
      ControlledAzureStorageContainerResource containerResource, StorageAccount storageAccount) {
    StorageSharedKeyCredential storageAccountKey =
        storageAccountKeyProvider.getStorageAccountKey(
            containerResource.getWorkspaceId(), storageAccount.name());

    return new BlobContainerClientBuilder()
        .credential(storageAccountKey)
        .endpoint(storageAccount.endPoints().primary().blob())
        .httpClient(HttpClient.createDefault())
        .containerName(containerResource.getStorageContainerName())
        .buildClient();
  }

  /**
   * Builds a blob container client for the given storage data object.
   *
   * @param storageData Storage data object we want a container client for
   * @return An azure blob container client
   */
  public BlobContainerClient buildBlobContainerClient(StorageData storageData) {
    StorageSharedKeyCredential storageAccountKey =
        storageAccountKeyProvider.getStorageAccountKey(
            storageData.storageContainerResource().getWorkspaceId(),
            storageData.storageAccountName());

    return new BlobContainerClientBuilder()
        .credential(storageAccountKey)
        .endpoint(storageData.endpoint())
        .httpClient(HttpClient.createDefault())
        .containerName(storageData.storageContainerResource().getStorageContainerName())
        .buildClient();
  }

  /**
   * Fetches the parent Azure storage account data for a given container resource, either from the
   * workspace's storage account (if present), or the parent landing zone. The requesting user must
   * have READ on the container
   *
   * @param workspaceUuid Workspace in which the container resides
   * @param storageContainerUuid WSM resource ID for the storage container
   * @param userRequest User request
   * @throws IllegalStateException if no shared storage account is present
   * @return StorageData object
   */
  public StorageData getStorageAccountData(
      UUID workspaceUuid, UUID storageContainerUuid, AuthenticatedUserRequest userRequest) {
    // Creating an AzureStorageContainerSasToken requires checking the user's access to both the
    // storage container and storage account resource
    final ControlledAzureStorageContainerResource storageContainerResource =
        controlledResourceMetadataManager
            .validateControlledResourceAndAction(
                userRequest,
                workspaceUuid,
                storageContainerUuid,
                SamConstants.SamControlledResourceActions.READ_ACTION)
            .castByEnum(WsmResourceType.CONTROLLED_AZURE_STORAGE_CONTAINER);
    // get details from LZ shared storage account
    var bearerToken = new BearerToken(samService.getWsmServiceAccountToken());
    UUID landingZoneId = landingZoneApiDispatch.getLandingZoneId(bearerToken, workspaceUuid);
    Optional<ApiAzureLandingZoneDeployedResource> existingSharedStorageAccount =
        landingZoneApiDispatch.getSharedStorageAccount(bearerToken, landingZoneId);
    if (existingSharedStorageAccount.isEmpty()) {
      // redefine exception
      throw new IllegalStateException(
          String.format(
              "Shared storage account not found. LandingZoneId='%s'."
                  + " Please validate that landing zone deployment complete.",
              landingZoneId));
    }
    var storageManager =
        crlService.getStorageManager(
            azureCloudContextService.getRequiredAzureCloudContext(workspaceUuid),
            azureConfiguration);
    StorageAccount storageAccount =
        storageManager
            .storageAccounts()
            .getById(existingSharedStorageAccount.get().getResourceId());
    return new StorageData(
        storageAccount.name(),
        storageAccount.endPoints().primary().blob().toLowerCase(Locale.ROOT),
        storageContainerResource);
  }
}

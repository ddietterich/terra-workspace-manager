package bio.terra.workspace.app.controller;

import static bio.terra.workspace.app.controller.shared.PropertiesUtils.convertApiPropertyToMap;
import static bio.terra.workspace.app.controller.shared.PropertiesUtils.convertMapToApiProperties;
import static bio.terra.workspace.common.utils.ControllerValidationUtils.validatePropertiesDeleteRequestBody;
import static bio.terra.workspace.common.utils.ControllerValidationUtils.validatePropertiesUpdateRequestBody;

import bio.terra.policy.model.TpsPaoGetResult;
import bio.terra.policy.model.TpsPaoUpdateResult;
import bio.terra.policy.model.TpsPolicyInputs;
import bio.terra.policy.model.TpsUpdateMode;
import bio.terra.workspace.app.configuration.external.FeatureConfiguration;
import bio.terra.workspace.app.controller.shared.JobApiUtils;
import bio.terra.workspace.common.exception.FeatureNotSupportedException;
import bio.terra.workspace.common.logging.model.ActivityLogChangeDetails;
import bio.terra.workspace.common.logging.model.ActivityLogChangedTarget;
import bio.terra.workspace.common.utils.ControllerValidationUtils;
import bio.terra.workspace.db.ResourceDao;
import bio.terra.workspace.db.WorkspaceActivityLogDao;
import bio.terra.workspace.db.exception.WorkspaceNotFoundException;
import bio.terra.workspace.generated.controller.WorkspaceApi;
import bio.terra.workspace.generated.model.ApiAwsContext;
import bio.terra.workspace.generated.model.ApiAzureContext;
import bio.terra.workspace.generated.model.ApiCloneWorkspaceRequest;
import bio.terra.workspace.generated.model.ApiCloneWorkspaceResult;
import bio.terra.workspace.generated.model.ApiClonedWorkspace;
import bio.terra.workspace.generated.model.ApiCloudPlatform;
import bio.terra.workspace.generated.model.ApiCreateCloudContextRequest;
import bio.terra.workspace.generated.model.ApiCreateCloudContextResult;
import bio.terra.workspace.generated.model.ApiCreateWorkspaceRequestBody;
import bio.terra.workspace.generated.model.ApiCreatedWorkspace;
import bio.terra.workspace.generated.model.ApiGcpContext;
import bio.terra.workspace.generated.model.ApiGrantRoleRequestBody;
import bio.terra.workspace.generated.model.ApiIamRole;
import bio.terra.workspace.generated.model.ApiJobReport.StatusEnum;
import bio.terra.workspace.generated.model.ApiMergeCheckRequest;
import bio.terra.workspace.generated.model.ApiProperties;
import bio.terra.workspace.generated.model.ApiProperty;
import bio.terra.workspace.generated.model.ApiRegions;
import bio.terra.workspace.generated.model.ApiRoleBinding;
import bio.terra.workspace.generated.model.ApiRoleBindingList;
import bio.terra.workspace.generated.model.ApiUpdateWorkspaceRequestBody;
import bio.terra.workspace.generated.model.ApiWorkspaceDescription;
import bio.terra.workspace.generated.model.ApiWorkspaceDescriptionList;
import bio.terra.workspace.generated.model.ApiWorkspaceStageModel;
import bio.terra.workspace.generated.model.ApiWsmPolicyExplainResult;
import bio.terra.workspace.generated.model.ApiWsmPolicyInput;
import bio.terra.workspace.generated.model.ApiWsmPolicyMergeCheckResult;
import bio.terra.workspace.generated.model.ApiWsmPolicyUpdateRequest;
import bio.terra.workspace.generated.model.ApiWsmPolicyUpdateResult;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.iam.AuthenticatedUserRequestFactory;
import bio.terra.workspace.service.iam.SamRethrow;
import bio.terra.workspace.service.iam.SamService;
import bio.terra.workspace.service.iam.exception.InvalidRoleException;
import bio.terra.workspace.service.iam.model.SamConstants;
import bio.terra.workspace.service.iam.model.SamConstants.SamWorkspaceAction;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import bio.terra.workspace.service.job.JobService;
import bio.terra.workspace.service.logging.WorkspaceActivityLogService;
import bio.terra.workspace.service.petserviceaccount.PetSaService;
import bio.terra.workspace.service.policy.TpsApiConversionUtils;
import bio.terra.workspace.service.policy.TpsApiDispatch;
import bio.terra.workspace.service.policy.model.PolicyExplainResult;
import bio.terra.workspace.service.resource.controlled.model.ControlledResource;
import bio.terra.workspace.service.spendprofile.SpendProfileId;
import bio.terra.workspace.service.workspace.AwsCloudContextService;
import bio.terra.workspace.service.workspace.AzureCloudContextService;
import bio.terra.workspace.service.workspace.GcpCloudContextService;
import bio.terra.workspace.service.workspace.WorkspaceService;
import bio.terra.workspace.service.workspace.exceptions.StageDisabledException;
import bio.terra.workspace.service.workspace.model.AwsCloudContext;
import bio.terra.workspace.service.workspace.model.AzureCloudContext;
import bio.terra.workspace.service.workspace.model.CloudContextHolder;
import bio.terra.workspace.service.workspace.model.CloudPlatform;
import bio.terra.workspace.service.workspace.model.GcpCloudContext;
import bio.terra.workspace.service.workspace.model.OperationType;
import bio.terra.workspace.service.workspace.model.Workspace;
import bio.terra.workspace.service.workspace.model.WorkspaceDescription;
import bio.terra.workspace.service.workspace.model.WorkspaceStage;
import io.opencensus.contrib.spring.aop.Traced;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class WorkspaceApiController extends ControllerBase implements WorkspaceApi {
  private static final Logger logger = LoggerFactory.getLogger(WorkspaceApiController.class);
  private final WorkspaceService workspaceService;
  private final JobService jobService;
  private final JobApiUtils jobApiUtils;
  private final GcpCloudContextService gcpCloudContextService;
  private final AzureCloudContextService azureCloudContextService;
  private final AwsCloudContextService awsCloudContextService;
  private final PetSaService petSaService;
  private final TpsApiDispatch tpsApiDispatch;
  private final WorkspaceActivityLogDao workspaceActivityLogDao;
  private final FeatureConfiguration featureConfiguration;
  private final WorkspaceActivityLogService workspaceActivityLogService;
  private final ResourceDao resourceDao;

  @Autowired
  public WorkspaceApiController(
      AuthenticatedUserRequestFactory authenticatedUserRequestFactory,
      HttpServletRequest request,
      SamService samService,
      WorkspaceService workspaceService,
      JobService jobService,
      JobApiUtils jobApiUtils,
      GcpCloudContextService gcpCloudContextService,
      AzureCloudContextService azureCloudContextService,
      AwsCloudContextService awsCloudContextService,
      PetSaService petSaService,
      TpsApiDispatch tpsApiDispatch,
      WorkspaceActivityLogDao workspaceActivityLogDao,
      FeatureConfiguration featureConfiguration,
      WorkspaceActivityLogService workspaceActivityLogService,
      ResourceDao resourceDao) {
    super(authenticatedUserRequestFactory, request, samService);
    this.workspaceService = workspaceService;
    this.jobService = jobService;
    this.jobApiUtils = jobApiUtils;
    this.gcpCloudContextService = gcpCloudContextService;
    this.azureCloudContextService = azureCloudContextService;
    this.awsCloudContextService = awsCloudContextService;
    this.petSaService = petSaService;
    this.tpsApiDispatch = tpsApiDispatch;
    this.workspaceActivityLogDao = workspaceActivityLogDao;
    this.featureConfiguration = featureConfiguration;
    this.workspaceActivityLogService = workspaceActivityLogService;
    this.resourceDao = resourceDao;
  }

  @Traced
  @Override
  public ResponseEntity<ApiCreatedWorkspace> createWorkspace(
      @RequestBody ApiCreateWorkspaceRequestBody body) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();

    try {
      workspaceService.getWorkspace(body.getId());
      return new ResponseEntity<>(HttpStatus.CONFLICT);
    } catch (WorkspaceNotFoundException ex) {
      logger.info(
          "Creating workspace {} for {} subject {}",
          body.getId(),
          userRequest.getEmail(),
          userRequest.getSubjectId());
    }

    // Unlike other operations, there's no Sam permission required to create a workspace. As long as
    // a user is enabled, they can call this endpoint.

    // Existing client libraries should not need to know about the stage, as they won't use any of
    // the features it gates. If stage isn't specified in a create request, we default to
    // RAWLS_WORKSPACE.
    ApiWorkspaceStageModel requestStage = body.getStage();
    requestStage = (requestStage == null ? ApiWorkspaceStageModel.RAWLS_WORKSPACE : requestStage);
    WorkspaceStage internalStage = WorkspaceStage.fromApiModel(requestStage);
    Optional<SpendProfileId> spendProfileId =
        Optional.ofNullable(body.getSpendProfile()).map(SpendProfileId::new);

    // ET uses userFacingId; CWB doesn't. Schema enforces that userFacingId must be set. CWB doesn't
    // pass userFacingId in request, so use id.
    String userFacingId =
        Optional.ofNullable(body.getUserFacingId()).orElse(body.getId().toString());
    ControllerValidationUtils.validateUserFacingId(userFacingId);

    // Validate that this workspace can have policies attached, if necessary.
    TpsPolicyInputs policies = null;
    if (body.getPolicies() != null) {
      if (!featureConfiguration.isTpsEnabled()) {
        throw new FeatureNotSupportedException(
            "TPS is not enabled on this instance of Workspace Manager, do not specify the policy field of a CreateWorkspace request.");
      }
      if (body.getStage() == ApiWorkspaceStageModel.RAWLS_WORKSPACE) {
        throw new StageDisabledException(
            "Cannot apply policies to a RAWLS_WORKSPACE stage workspace");
      }
      policies = TpsApiConversionUtils.tpsFromApiTpsPolicyInputs(body.getPolicies());
    }

    Workspace workspace =
        Workspace.builder()
            .workspaceId(body.getId())
            .userFacingId(userFacingId)
            .displayName(body.getDisplayName())
            .description(body.getDescription())
            .spendProfileId(spendProfileId.orElse(null))
            .workspaceStage(internalStage)
            .properties(convertApiPropertyToMap(body.getProperties()))
            .createdByEmail(getSamService().getUserEmailFromSamAndRethrowOnInterrupt(userRequest))
            .build();
    UUID createdWorkspaceUuid =
        workspaceService.createWorkspace(
            workspace, policies, body.getApplicationIds(), userRequest);

    ApiCreatedWorkspace responseWorkspace = new ApiCreatedWorkspace().id(createdWorkspaceUuid);
    logger.info("Created workspace {} for {}", responseWorkspace, userRequest.getEmail());

    return new ResponseEntity<>(responseWorkspace, HttpStatus.OK);
  }

  @Traced
  @Override
  public ResponseEntity<ApiWorkspaceDescriptionList> listWorkspaces(
      Integer offset, Integer limit, ApiIamRole minimumHighestRole) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    logger.info("Listing workspaces for {}", userRequest.getEmail());
    ControllerValidationUtils.validatePaginationParams(offset, limit);
    // Can't set default in yaml (https://stackoverflow.com/a/68542868/6447189), so set here.
    if (minimumHighestRole == null) {
      minimumHighestRole = ApiIamRole.READER;
    }

    // Unlike other operations, there's no Sam permission required to list workspaces. As long as
    // a user is enabled, they can call this endpoint, though they may not have any workspaces they
    // can read.
    List<WorkspaceDescription> workspacesAndHighestRoles =
        workspaceService.getWorkspaceDescriptions(
            userRequest, offset, limit, WsmIamRole.fromApiModel(minimumHighestRole));
    var response =
        new ApiWorkspaceDescriptionList()
            .workspaces(
                workspacesAndHighestRoles.stream()
                    .map(
                        workspaceAndHighestRole ->
                            buildWorkspaceDescription(
                                workspaceAndHighestRole.workspace(),
                                workspaceAndHighestRole.highestRole(),
                                workspaceAndHighestRole.missingAuthDomains()))
                    .toList());
    return new ResponseEntity<>(response, HttpStatus.OK);
  }

  @Traced
  private ApiWorkspaceDescription buildWorkspaceDescription(
      Workspace workspace, WsmIamRole highestRole) {
    return buildWorkspaceDescription(
        workspace, highestRole, /*missingAuthDomains=*/ Collections.emptyList());
  }

  @Traced
  private ApiWorkspaceDescription buildWorkspaceDescription(
      Workspace workspace, WsmIamRole highestRole, List<String> missingAuthDomains) {
    UUID workspaceUuid = workspace.getWorkspaceId();
    ApiGcpContext gcpContext =
        gcpCloudContextService
            .getGcpCloudContext(workspaceUuid)
            .map(GcpCloudContext::toApi)
            .orElse(null);

    ApiAzureContext azureContext =
        azureCloudContextService
            .getAzureCloudContext(workspaceUuid)
            .map(AzureCloudContext::toApi)
            .orElse(null);

    ApiAwsContext awsContext =
        awsCloudContextService
            .getAwsCloudContext(workspaceUuid)
            .map(AwsCloudContext::toApi)
            .orElse(null);

    List<ApiWsmPolicyInput> workspacePolicies = null;
    if (featureConfiguration.isTpsEnabled()) {
      tpsApiDispatch.createPaoIfNotExist(workspaceUuid);
      TpsPaoGetResult workspacePao = tpsApiDispatch.getPao(workspaceUuid);
      workspacePolicies = TpsApiConversionUtils.apiEffectivePolicyListFromTpsPao(workspacePao);
    }

    // When we have another cloud context, we will need to do a similar retrieval for it.
    var lastChangeDetailsOptional =
        workspaceActivityLogService.getLastUpdatedDetails(workspaceUuid);

    if (highestRole == WsmIamRole.DISCOVERER) {
      workspace = Workspace.stripWorkspaceForRequesterWithOnlyDiscovererRole(workspace);
    }

    // Convert the property map to API format
    ApiProperties apiProperties = convertMapToApiProperties(workspace.getProperties());

    return new ApiWorkspaceDescription()
        .id(workspaceUuid)
        .userFacingId(workspace.getUserFacingId())
        .displayName(workspace.getDisplayName().orElse(null))
        .description(workspace.getDescription().orElse(null))
        .highestRole(highestRole.toApiModel())
        .properties(apiProperties)
        .spendProfile(workspace.getSpendProfileId().map(SpendProfileId::getId).orElse(null))
        .stage(workspace.getWorkspaceStage().toApiModel())
        .gcpContext(gcpContext)
        .azureContext(azureContext)
        .awsContext(awsContext)
        .createdDate(workspace.createdDate())
        .createdBy(workspace.createdByEmail())
        .lastUpdatedDate(
            lastChangeDetailsOptional
                .map(ActivityLogChangeDetails::changeDate)
                .orElse(workspace.createdDate()))
        .lastUpdatedBy(
            lastChangeDetailsOptional
                .map(ActivityLogChangeDetails::actorEmail)
                .orElse(workspace.createdByEmail()))
        .policies(workspacePolicies)
        .missingAuthDomains(missingAuthDomains);
  }

  @Traced
  @Override
  public ResponseEntity<ApiWorkspaceDescription> getWorkspace(
      @PathVariable("workspaceId") UUID uuid, ApiIamRole minimumHighestRole) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    logger.info("Getting workspace {} for {}", uuid, userRequest.getEmail());
    // Can't set default in yaml (https://stackoverflow.com/a/68542868/6447189), so set here.
    if (minimumHighestRole == null) {
      minimumHighestRole = ApiIamRole.READER;
    }
    String samAction = WsmIamRole.fromApiModel(minimumHighestRole).toSamAction();
    Workspace workspace = workspaceService.validateWorkspaceAndAction(userRequest, uuid, samAction);

    WsmIamRole highestRole = workspaceService.getHighestRole(uuid, userRequest);
    ApiWorkspaceDescription desc = buildWorkspaceDescription(workspace, highestRole);
    logger.info("Got workspace {} for {}", desc, userRequest.getEmail());

    return new ResponseEntity<>(desc, HttpStatus.OK);
  }

  @Traced
  @Override
  public ResponseEntity<ApiWorkspaceDescription> getWorkspaceByUserFacingId(
      @PathVariable("workspaceUserFacingId") String userFacingId, ApiIamRole minimumHighestRole) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    logger.info("Getting workspace {} for {}", userFacingId, userRequest.getEmail());
    // Can't set default in yaml (https://stackoverflow.com/a/68542868/6447189), so set here.
    if (minimumHighestRole == null) {
      minimumHighestRole = ApiIamRole.READER;
    }
    // Authz check is inside workspaceService here as we would need the UUID to check Sam, but
    // we only have the UFID at this point.

    Workspace workspace =
        workspaceService.getWorkspaceByUserFacingId(
            userFacingId, userRequest, WsmIamRole.fromApiModel(minimumHighestRole));
    WsmIamRole highestRole =
        workspaceService.getHighestRole(workspace.getWorkspaceId(), userRequest);
    ApiWorkspaceDescription desc = buildWorkspaceDescription(workspace, highestRole);
    logger.info("Got workspace {} for {}", desc, userRequest.getEmail());

    return new ResponseEntity<>(desc, HttpStatus.OK);
  }

  @Traced
  @Override
  public ResponseEntity<ApiWorkspaceDescription> updateWorkspace(
      @PathVariable("workspaceId") UUID workspaceUuid,
      @RequestBody ApiUpdateWorkspaceRequestBody body) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    logger.info("Updating workspace {} for {}", workspaceUuid, userRequest.getEmail());

    if (body.getUserFacingId() != null) {
      ControllerValidationUtils.validateUserFacingId(body.getUserFacingId());
    }
    workspaceService.validateWorkspaceAndAction(
        userRequest, workspaceUuid, SamConstants.SamWorkspaceAction.WRITE);

    Workspace workspace =
        workspaceService.updateWorkspace(
            workspaceUuid,
            body.getUserFacingId(),
            body.getDisplayName(),
            body.getDescription(),
            userRequest);
    WsmIamRole highestRole = workspaceService.getHighestRole(workspaceUuid, userRequest);
    ApiWorkspaceDescription desc = buildWorkspaceDescription(workspace, highestRole);
    logger.info("Updated workspace {} for {}", desc, userRequest.getEmail());

    return new ResponseEntity<>(desc, HttpStatus.OK);
  }

  @Traced
  @Override
  public ResponseEntity<ApiWsmPolicyUpdateResult> updatePolicies(
      @PathVariable("workspaceId") UUID workspaceId, @RequestBody ApiWsmPolicyUpdateRequest body) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    logger.info("Updating workspace policies {} for {}", workspaceId, userRequest.getEmail());

    workspaceService.validateWorkspaceAndAction(userRequest, workspaceId, SamWorkspaceAction.WRITE);

    featureConfiguration.tpsEnabledCheck();
    TpsPolicyInputs adds = TpsApiConversionUtils.tpsFromApiTpsPolicyInputs(body.getAddAttributes());
    TpsPolicyInputs removes =
        TpsApiConversionUtils.tpsFromApiTpsPolicyInputs(body.getRemoveAttributes());
    TpsUpdateMode updateMode = TpsApiConversionUtils.tpsFromApiTpsUpdateMode(body.getUpdateMode());

    TpsPaoUpdateResult result = tpsApiDispatch.updatePao(workspaceId, adds, removes, updateMode);

    if (Boolean.TRUE.equals(result.isUpdateApplied())) {
      workspaceActivityLogService.writeActivity(
          userRequest,
          workspaceId,
          OperationType.UPDATE,
          workspaceId.toString(),
          ActivityLogChangedTarget.POLICIES);
      logger.info(
          "Finished updating workspace policies {} for {}", workspaceId, userRequest.getEmail());
    } else {
      logger.warn(
          "Workspace policies update failed to apply to {} for {}",
          workspaceId,
          userRequest.getEmail());
    }

    ApiWsmPolicyUpdateResult apiResult = TpsApiConversionUtils.apiFromTpsUpdateResult(result);
    return new ResponseEntity<>(apiResult, HttpStatus.OK);
  }

  @Traced
  @Override
  public ResponseEntity<Void> deleteWorkspace(@PathVariable("workspaceId") UUID uuid) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    logger.info("Deleting workspace {} for {}", uuid, userRequest.getEmail());
    Workspace workspace =
        workspaceService.validateWorkspaceAndAction(userRequest, uuid, SamWorkspaceAction.DELETE);
    workspaceService.deleteWorkspace(workspace, userRequest);
    logger.info("Deleted workspace {} for {}", uuid, userRequest.getEmail());

    return new ResponseEntity<>(HttpStatus.NO_CONTENT);
  }

  @Traced
  @Override
  public ResponseEntity<Void> deleteWorkspaceProperties(
      @PathVariable("workspaceId") UUID workspaceUuid, @RequestBody List<String> propertyKeys) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    workspaceService.validateWorkspaceAndAction(
        userRequest, workspaceUuid, SamWorkspaceAction.DELETE);
    validatePropertiesDeleteRequestBody(propertyKeys);
    logger.info("Deleting the properties in workspace {}", workspaceUuid);
    workspaceService.validateWorkspaceAndAction(
        userRequest, workspaceUuid, SamWorkspaceAction.DELETE);
    workspaceService.deleteWorkspaceProperties(workspaceUuid, propertyKeys, userRequest);
    logger.info("Deleted the properties in workspace {}", workspaceUuid);

    return new ResponseEntity<>(HttpStatus.NO_CONTENT);
  }

  @Traced
  @Override
  public ResponseEntity<Void> updateWorkspaceProperties(
      @PathVariable("workspaceId") UUID workspaceUuid, @RequestBody List<ApiProperty> properties) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    workspaceService.validateWorkspaceAndAction(
        userRequest, workspaceUuid, SamWorkspaceAction.WRITE);
    validatePropertiesUpdateRequestBody(properties);
    Map<String, String> propertyMap = convertApiPropertyToMap(properties);
    logger.info("Updating the properties {} in workspace {}", propertyMap, workspaceUuid);
    workspaceService.updateWorkspaceProperties(workspaceUuid, propertyMap, userRequest);
    logger.info("Updated the properties {} in workspace {}", propertyMap, workspaceUuid);

    return new ResponseEntity<>(HttpStatus.NO_CONTENT);
  }

  @Traced
  @Override
  public ResponseEntity<Void> grantRole(
      @PathVariable("workspaceId") UUID workspaceUuid,
      @PathVariable("role") ApiIamRole role,
      @RequestBody ApiGrantRoleRequestBody body) {
    ControllerValidationUtils.validateEmail(body.getMemberEmail());
    if (role == ApiIamRole.APPLICATION) {
      throw new InvalidRoleException(
          "Users cannot grant role APPLICATION. Use application registration instead.");
    }

    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    logger.info("Grant role {} on workspace {} to {}", role, workspaceUuid, userRequest.getEmail());

    // TODO: we do not define actions for setting IAM; OWN will do for now
    workspaceService.validateWorkspaceAndAction(userRequest, workspaceUuid, SamWorkspaceAction.OWN);
    workspaceService.grantRole(workspaceUuid, WsmIamRole.fromApiModel(role), body.getMemberEmail(), userRequest);
    return new ResponseEntity<>(HttpStatus.NO_CONTENT);
  }

  @Traced
  @Override
  public ResponseEntity<Void> removeRole(
      @PathVariable("workspaceId") UUID workspaceUuid,
      @PathVariable("role") ApiIamRole role,
      @PathVariable("memberEmail") String memberEmail) {
    ControllerValidationUtils.validateEmail(memberEmail);
    if (role == ApiIamRole.APPLICATION) {
      throw new InvalidRoleException(
          "Users cannot remove role APPLICATION. Use application registration instead.");
    }
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    Workspace workspace =
        workspaceService.validateMcWorkspaceAndAction(userRequest, workspaceUuid, SamWorkspaceAction.OWN);
    workspaceService.removeWorkspaceRoleFromUser(
        workspace, WsmIamRole.fromApiModel(role), memberEmail, userRequest);
    return new ResponseEntity<>(HttpStatus.NO_CONTENT);
  }

  @Traced
  @Override
  public ResponseEntity<ApiRoleBindingList> getRoles(@PathVariable("workspaceId") UUID uuid) {
    // No additional authz check as this is just a wrapper around a Sam endpoint.
    List<bio.terra.workspace.service.iam.model.RoleBinding> bindingList =
        SamRethrow.onInterrupted(
            () -> getSamService().listRoleBindings(uuid, getAuthenticatedInfo()),
            "listRoleBindings");
    ApiRoleBindingList responseList = new ApiRoleBindingList();
    for (bio.terra.workspace.service.iam.model.RoleBinding roleBinding : bindingList) {
      responseList.add(
          new ApiRoleBinding().role(roleBinding.role().toApiModel()).members(roleBinding.users()));
    }
    return new ResponseEntity<>(responseList, HttpStatus.OK);
  }

  @Traced
  @Override
  public ResponseEntity<ApiCreateCloudContextResult> createCloudContext(
      UUID uuid, @Valid ApiCreateCloudContextRequest body) {
    ApiCloudPlatform cloudPlatform = body.getCloudPlatform();
    ControllerValidationUtils.validateCloudPlatform(cloudPlatform);
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    String jobId = body.getJobControl().getId();
    String resultPath = getAsyncResultEndpoint(jobId);
    Workspace workspace =
        workspaceService.validateMcWorkspaceAndAction(userRequest, uuid, SamWorkspaceAction.WRITE);

    switch (cloudPlatform) {
      case GCP -> workspaceService.createGcpCloudContext(workspace, jobId, userRequest, resultPath);
      case AZURE -> workspaceService.createAzureCloudContext(
          workspace, jobId, userRequest, resultPath);
      case AWS -> workspaceService.createAwsCloudContext(workspace, jobId, userRequest, resultPath);
      default -> throw new FeatureNotSupportedException(
          "Cloud context creation not supported for cloud platform " + cloudPlatform);
    }

    ApiCreateCloudContextResult response = fetchCreateCloudContextResult(jobId);
    return new ResponseEntity<>(response, getAsyncResponseCode(response.getJobReport()));
  }

  @Traced
  @Override
  public ResponseEntity<ApiCreateCloudContextResult> getCreateCloudContextResult(
      UUID uuid, String jobId) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    jobService.verifyUserAccess(jobId, userRequest, uuid);
    ApiCreateCloudContextResult response = fetchCreateCloudContextResult(jobId);
    return new ResponseEntity<>(response, getAsyncResponseCode(response.getJobReport()));
  }

  private ApiCreateCloudContextResult fetchCreateCloudContextResult(String jobId) {
    JobApiUtils.AsyncJobResult<CloudContextHolder> jobResult =
        jobApiUtils.retrieveAsyncJobResult(jobId, CloudContextHolder.class);

    ApiGcpContext gcpContext = null;
    ApiAzureContext azureContext = null;
    ApiAwsContext awsContext = null;

    if (jobResult.getJobReport().getStatus().equals(StatusEnum.SUCCEEDED)) {
      gcpContext =
          Optional.ofNullable(jobResult.getResult().getGcpCloudContext())
              .map(c -> new ApiGcpContext().projectId(c.getGcpProjectId()))
              .orElse(null);

      azureContext =
          Optional.ofNullable(jobResult.getResult().getAzureCloudContext())
              .map(
                  c ->
                      new ApiAzureContext()
                          .tenantId(c.getAzureTenantId())
                          .subscriptionId(c.getAzureSubscriptionId())
                          .resourceGroupId(c.getAzureResourceGroupId()))
              .orElse(null);

      awsContext =
          Optional.ofNullable(jobResult.getResult().getAwsCloudContext())
              .map(
                  c ->
                      new ApiAwsContext()
                          .majorVersion(c.getMajorVersion())
                          .organizationId(c.getOrganizationId())
                          .accountId(c.getAccountId())
                          .tenantAlias(c.getTenantAlias())
                          .environmentAlias(c.getEnvironmentAlias()))
              .orElse(null);
    }

    return new ApiCreateCloudContextResult()
        .jobReport(jobResult.getJobReport())
        .errorReport(jobResult.getApiErrorReport())
        .gcpContext(gcpContext)
        .azureContext(azureContext)
        .awsContext(awsContext);
  }

  @Traced
  @Override
  public ResponseEntity<Void> deleteCloudContext(UUID uuid, ApiCloudPlatform cloudPlatform) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    ControllerValidationUtils.validateCloudPlatform(cloudPlatform);
    Workspace workspace =
        workspaceService.validateMcWorkspaceAndAction(userRequest, uuid, SamWorkspaceAction.WRITE);

    switch (cloudPlatform) {
      case GCP -> workspaceService.deleteGcpCloudContext(workspace, userRequest);
      case AZURE -> workspaceService.deleteAzureCloudContext(workspace, userRequest);
      case AWS -> workspaceService.deleteAwsCloudContext(workspace, userRequest);
      default -> throw new FeatureNotSupportedException(
          "Cloud context deletion not supported for cloud platform " + cloudPlatform);
    }

    return new ResponseEntity<>(HttpStatus.NO_CONTENT);
  }

  @Traced
  @Override
  public ResponseEntity<Void> enablePet(UUID workspaceUuid) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    // TODO(PF-1007): This would be a nice use for an authorized workspace ID.
    // Validate that the user is a workspace member, as enablePetServiceAccountImpersonation does
    // not authenticate.
    workspaceService.validateMcWorkspaceAndAction(
        userRequest, workspaceUuid, SamWorkspaceAction.READ);
    petSaService.enablePetServiceAccountImpersonation(
        workspaceUuid,
        getSamService().getUserEmailFromSamAndRethrowOnInterrupt(userRequest),
        userRequest);
    return new ResponseEntity<>(HttpStatus.NO_CONTENT);
  }

  /**
   * Clone an entire workspace by creating a new workspace and cloning the workspace's resources
   * into it.
   *
   * @param workspaceUuid - ID of source workspace
   * @param body - request body
   * @return - result structure for the overall clone operation with details for each resource
   */
  @Traced
  @Override
  public ResponseEntity<ApiCloneWorkspaceResult> cloneWorkspace(
      UUID workspaceUuid, @Valid ApiCloneWorkspaceRequest body) {
    final AuthenticatedUserRequest petRequest = getCloningCredentials(workspaceUuid);

    // Clone is creating the destination workspace so unlike other clone operations there's no
    // additional authz check for the destination. As long as the user is enabled in Sam, they can
    // create a new workspace.
    final Workspace sourceWorkspace =
        workspaceService.validateWorkspaceAndAction(
            petRequest, workspaceUuid, SamWorkspaceAction.READ);

    Optional<SpendProfileId> spendProfileId =
        Optional.ofNullable(body.getSpendProfile()).map(SpendProfileId::new);

    // Accept a target workspace id if one is provided. This allows Rawls to specify an
    // existing workspace id. WSM then creates the WSMspace supporting the Rawls workspace.
    UUID destinationWorkspaceId =
        Optional.ofNullable(body.getDestinationWorkspaceId()).orElse(UUID.randomUUID());

    // ET uses userFacingId; CWB doesn't. Schema enforces that userFacingId must be set. CWB doesn't
    // pass userFacingId in request, so use id.
    String destinationUserFacingId =
        Optional.ofNullable(body.getUserFacingId()).orElse(destinationWorkspaceId.toString());
    ControllerValidationUtils.validateUserFacingId(destinationUserFacingId);

    // If user does not specify the destinationWorkspace's displayName, then we will generate the
    // name followed the sourceWorkspace's displayName, if sourceWorkspace's displayName is null, we
    // will generate the name based on the sourceWorkspace's userFacingId.
    String generatedDisplayName =
        sourceWorkspace.getDisplayName().orElse(sourceWorkspace.getUserFacingId()) + " (Copy)";

    // Construct the target workspace object from the inputs
    // Policies are cloned in the flight instead of here so that they get cleaned appropriately if
    // the flight fails.
    final Workspace destinationWorkspace =
        Workspace.builder()
            .workspaceId(destinationWorkspaceId)
            .userFacingId(destinationUserFacingId)
            .spendProfileId(spendProfileId.orElse(null))
            .workspaceStage(sourceWorkspace.getWorkspaceStage())
            .displayName(Optional.ofNullable(body.getDisplayName()).orElse(generatedDisplayName))
            .description(body.getDescription())
            .properties(sourceWorkspace.getProperties())
            .createdByEmail(getSamService().getUserEmailFromSamAndRethrowOnInterrupt(petRequest))
            .build();

    final String jobId =
        workspaceService.cloneWorkspace(
            sourceWorkspace,
            petRequest,
            body.getLocation(),
            TpsApiConversionUtils.tpsFromApiTpsPolicyInputs(body.getAdditionalPolicies()),
            destinationWorkspace);

    final ApiCloneWorkspaceResult result = fetchCloneWorkspaceResult(jobId);
    final ApiClonedWorkspace clonedWorkspaceStub =
        new ApiClonedWorkspace()
            .destinationWorkspaceId(destinationWorkspaceId)
            .destinationUserFacingId(destinationUserFacingId)
            .sourceWorkspaceId(workspaceUuid);
    result.setWorkspace(clonedWorkspaceStub);
    return new ResponseEntity<>(result, getAsyncResponseCode(result.getJobReport()));
  }

  /**
   * Return the workspace clone result, including job result and error result.
   *
   * @param workspaceUuid - source workspace ID
   * @param jobId - ID of flight
   * @return - response with result
   */
  @Traced
  @Override
  public ResponseEntity<ApiCloneWorkspaceResult> getCloneWorkspaceResult(
      UUID workspaceUuid, String jobId) {
    final AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    jobService.verifyUserAccess(jobId, userRequest, workspaceUuid);
    final ApiCloneWorkspaceResult result = fetchCloneWorkspaceResult(jobId);
    return new ResponseEntity<>(result, getAsyncResponseCode(result.getJobReport()));
  }

  @Traced
  @Override
  public ResponseEntity<ApiRegions> listValidRegions(UUID workspaceId, ApiCloudPlatform platform) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    workspaceService.validateWorkspaceAndAction(userRequest, workspaceId, SamWorkspaceAction.READ);

    List<String> regions =
        tpsApiDispatch.listValidRegions(workspaceId, CloudPlatform.fromApiCloudPlatform(platform));

    ApiRegions apiRegions = new ApiRegions();
    apiRegions.addAll(regions);
    return new ResponseEntity<>(apiRegions, HttpStatus.OK);
  }

  @Traced
  @Override
  public ResponseEntity<ApiWsmPolicyExplainResult> explainPolicies(
      UUID workspaceId, Integer depth) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    workspaceService.validateWorkspaceAndAction(userRequest, workspaceId, SamWorkspaceAction.READ);
    PolicyExplainResult explainResult =
        tpsApiDispatch.explain(workspaceId, depth, workspaceService, userRequest);

    return new ResponseEntity<>(explainResult.toApi(), HttpStatus.OK);
  }

  @Traced
  @Override
  public ResponseEntity<ApiWsmPolicyMergeCheckResult> mergeCheck(
      UUID targetWorkspaceId, ApiMergeCheckRequest requestBody) {
    UUID sourceWorkspaceId = requestBody.getWorkspaceId();
    tpsApiDispatch.createPaoIfNotExist(sourceWorkspaceId);
    tpsApiDispatch.createPaoIfNotExist(targetWorkspaceId);

    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    workspaceService.validateWorkspaceAndAction(
        userRequest, targetWorkspaceId, SamWorkspaceAction.READ);
    TpsPaoUpdateResult dryRunResults =
        tpsApiDispatch.mergePao(targetWorkspaceId, sourceWorkspaceId, TpsUpdateMode.DRY_RUN);

    List<UUID> resourceWithConflicts = new ArrayList<>();

    for (var platform : ApiCloudPlatform.values()) {
      HashSet<String> validRegions =
          new HashSet<>(
              tpsApiDispatch.listValidRegions(
                  sourceWorkspaceId, CloudPlatform.fromApiCloudPlatform(platform)));

      List<ControlledResource> existingResources =
          resourceDao.listControlledResources(
              targetWorkspaceId, CloudPlatform.fromApiCloudPlatform(platform));

      for (var existingResource : existingResources) {
        if (validRegions.stream().noneMatch(existingResource.getRegion()::equalsIgnoreCase)) {
          resourceWithConflicts.add(existingResource.getResourceId());
        }
      }
    }
    ApiWsmPolicyMergeCheckResult updateResult =
        new ApiWsmPolicyMergeCheckResult()
            .conflicts(
                TpsApiConversionUtils.apiFromTpsPaoConflictList(dryRunResults.getConflicts()))
            .resourcesWithConflict(resourceWithConflicts);

    return new ResponseEntity<>(updateResult, HttpStatus.ACCEPTED);
  }

  // Retrieve the async result or progress for clone workspace.
  private ApiCloneWorkspaceResult fetchCloneWorkspaceResult(String jobId) {
    JobApiUtils.AsyncJobResult<ApiClonedWorkspace> jobResult =
        jobApiUtils.retrieveAsyncJobResult(jobId, ApiClonedWorkspace.class);
    return new ApiCloneWorkspaceResult()
        .jobReport(jobResult.getJobReport())
        .errorReport(jobResult.getApiErrorReport())
        .workspace(jobResult.getResult());
  }

  /**
   * Return Pet SA credentials if available, otherwise the user credentials associated with this
   * request. It's possible to clone a workspace that has no cloud context, and thus no (GCP) pet
   * account.
   *
   * @param workspaceUuid - ID of workspace to be cloned
   * @return user or pet request
   */
  private AuthenticatedUserRequest getCloningCredentials(UUID workspaceUuid) {
    final AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    return petSaService.getWorkspacePetCredentials(workspaceUuid, userRequest).orElse(userRequest);
  }
}

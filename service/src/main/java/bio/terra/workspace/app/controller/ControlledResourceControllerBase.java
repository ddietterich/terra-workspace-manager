package bio.terra.workspace.app.controller;

import static com.google.common.base.Preconditions.checkArgument;

import bio.terra.workspace.app.controller.shared.PropertiesUtils;
import bio.terra.workspace.generated.model.ApiControlledResourceCommonFields;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.iam.AuthenticatedUserRequestFactory;
import bio.terra.workspace.service.iam.SamService;
import bio.terra.workspace.service.resource.controlled.ControlledResourceService;
import bio.terra.workspace.service.resource.controlled.model.AccessScopeType;
import bio.terra.workspace.service.resource.controlled.model.ControlledResourceFields;
import bio.terra.workspace.service.resource.controlled.model.ManagedByType;
import bio.terra.workspace.service.resource.controlled.model.PrivateUserRole;
import bio.terra.workspace.service.resource.model.CloningInstructions;
import bio.terra.workspace.service.resource.model.WsmResourceType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

/**
 * Super class for controllers containing common code. The code in here requires the @Autowired
 * beans from the @Controller classes, so it is better as a superclass rather than static methods.
 */
public class ControlledResourceControllerBase extends ControllerBase {
  private final ControlledResourceService controlledResourceService;

  /**
   * The region field of these wsm resource type are filled during the creation flight because the
   * region is computed at runtime based on e.g. network and storage account.
   *
   * <p>Note: WSM Flexible resources are not cloud resources, so they do not require regions.
   */
  private static final List<WsmResourceType> WSM_RESOURCE_WITHOUT_REGION_IN_CREATION_PARAMS =
      List.of(
          WsmResourceType.CONTROLLED_AZURE_STORAGE_CONTAINER,
          WsmResourceType.CONTROLLED_AZURE_VM,
          WsmResourceType.CONTROLLED_GCP_AI_NOTEBOOK_INSTANCE,
          WsmResourceType.CONTROLLED_AZURE_BATCH_POOL,
          WsmResourceType.CONTROLLED_FLEXIBLE_RESOURCE);

  public ControlledResourceControllerBase(
      AuthenticatedUserRequestFactory authenticatedUserRequestFactory,
      HttpServletRequest request,
      ControlledResourceService controlledResourceService,
      SamService samService) {
    super(authenticatedUserRequestFactory, request, samService);
    this.controlledResourceService = controlledResourceService;
  }

  public ControlledResourceService getControlledResourceService() {
    return controlledResourceService;
  }

  public ControlledResourceFields toCommonFields(
      UUID workspaceUuid,
      ApiControlledResourceCommonFields apiCommonFields,
      String region,
      AuthenticatedUserRequest userRequest,
      WsmResourceType wsmResourceType) {

    ManagedByType managedBy = ManagedByType.fromApi(apiCommonFields.getManagedBy());
    AccessScopeType accessScopeType = AccessScopeType.fromApi(apiCommonFields.getAccessScope());
    PrivateUserRole privateUserRole =
        computePrivateUserRole(workspaceUuid, apiCommonFields, userRequest);
    String userEmail = getSamService().getUserEmailFromSamAndRethrowOnInterrupt(userRequest);

    if (!WSM_RESOURCE_WITHOUT_REGION_IN_CREATION_PARAMS.contains(wsmResourceType)) {
      checkArgument(
          region != null,
          "Controlled resource must have an associated region specified"
              + "on creation except for Azure storage containers, Azure VMs, Azure batch pools, "
              + "Vertex AI notebooks, and Flexible resources");
    }

    return ControlledResourceFields.builder()
        .workspaceUuid(workspaceUuid)
        .resourceId(
            Optional.ofNullable(apiCommonFields.getResourceId())
                .orElse(UUID.randomUUID())) // TODO: add duplicate resourceId check
        // https://broadworkbench.atlassian.net/browse/TOAZ-138
        .name(apiCommonFields.getName())
        .description(apiCommonFields.getDescription())
        .cloningInstructions(
            CloningInstructions.fromApiModel(apiCommonFields.getCloningInstructions()))
        .iamRole(privateUserRole.getRole())
        .assignedUser(privateUserRole.getUserEmail())
        .accessScope(accessScopeType)
        .managedBy(managedBy)
        .applicationId(controlledResourceService.getAssociatedApp(managedBy, userRequest))
        .properties(PropertiesUtils.convertApiPropertyToMap(apiCommonFields.getProperties()))
        .createdByEmail(userEmail)
        .region(region)
        .build();
  }
}

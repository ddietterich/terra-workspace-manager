package bio.terra.workspace.app.controller;

import static bio.terra.workspace.app.controller.shared.PropertiesUtils.convertApiPropertyToMap;
import static bio.terra.workspace.common.utils.ControllerValidationUtils.validatePropertiesDeleteRequestBody;
import static bio.terra.workspace.common.utils.ControllerValidationUtils.validatePropertiesUpdateRequestBody;

import bio.terra.workspace.common.utils.ControllerValidationUtils;
import bio.terra.workspace.db.FolderDao;
import bio.terra.workspace.generated.controller.ResourceApi;
import bio.terra.workspace.generated.model.ApiProperty;
import bio.terra.workspace.generated.model.ApiResourceAttributesUnion;
import bio.terra.workspace.generated.model.ApiResourceDescription;
import bio.terra.workspace.generated.model.ApiResourceList;
import bio.terra.workspace.generated.model.ApiResourceMetadata;
import bio.terra.workspace.generated.model.ApiResourceType;
import bio.terra.workspace.generated.model.ApiStewardshipType;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.iam.AuthenticatedUserRequestFactory;
import bio.terra.workspace.service.iam.model.SamConstants;
import bio.terra.workspace.service.resource.ResourceValidationUtils;
import bio.terra.workspace.service.resource.WsmResourceService;
import bio.terra.workspace.service.resource.model.StewardshipType;
import bio.terra.workspace.service.resource.model.WsmResource;
import bio.terra.workspace.service.resource.model.WsmResourceFamily;
import bio.terra.workspace.service.resource.referenced.cloud.gcp.ReferencedResourceService;
import bio.terra.workspace.service.workspace.WorkspaceService;
import com.google.common.annotations.VisibleForTesting;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ResourceApiController implements ResourceApi {

  private final WsmResourceService resourceService;
  private final WorkspaceService workspaceService;
  private final ReferencedResourceService referencedResourceService;

  private final AuthenticatedUserRequestFactory authenticatedUserRequestFactory;
  private final HttpServletRequest request;
  private final FolderDao folderDao;

  @Autowired
  public ResourceApiController(
      WsmResourceService resourceService,
      WorkspaceService workspaceService,
      ReferencedResourceService referencedResourceService,
      AuthenticatedUserRequestFactory authenticatedUserRequestFactory,
      HttpServletRequest request,
      FolderDao folderDao) {
    this.resourceService = resourceService;
    this.workspaceService = workspaceService;
    this.referencedResourceService = referencedResourceService;
    this.authenticatedUserRequestFactory = authenticatedUserRequestFactory;
    this.request = request;
    this.folderDao = folderDao;
  }

  private AuthenticatedUserRequest getAuthenticatedInfo() {
    return authenticatedUserRequestFactory.from(request);
  }

  @Override
  public ResponseEntity<ApiResourceList> enumerateResources(
      UUID workspaceUuid,
      @Valid @RequestParam(value = "offset", required = false, defaultValue = "0") Integer offset,
      @Valid @RequestParam(value = "limit", required = false, defaultValue = "10") Integer limit,
      @Valid ApiResourceType resource,
      @Valid ApiStewardshipType stewardship) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    ControllerValidationUtils.validatePaginationParams(offset, limit);
    workspaceService.validateWorkspaceAndAction(
        userRequest, workspaceUuid, SamConstants.SamWorkspaceAction.READ);

    List<WsmResource> wsmResources =
        resourceService.enumerateResources(
            workspaceUuid,
            WsmResourceFamily.fromApiOptional(resource),
            StewardshipType.fromApiOptional(stewardship),
            offset,
            limit);

    List<ApiResourceDescription> apiResourceDescriptionList =
        wsmResources.stream().map(this::makeApiResourceDescription).collect(Collectors.toList());

    var apiResourceList = new ApiResourceList().resources(apiResourceDescriptionList);
    return new ResponseEntity<>(apiResourceList, HttpStatus.OK);
  }

  @Override
  public ResponseEntity<Boolean> checkReferenceAccess(UUID workspaceUuid, UUID resourceId) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    workspaceService.validateWorkspaceAndAction(
        userRequest, workspaceUuid, SamConstants.SamWorkspaceAction.READ);
    boolean isValid = referencedResourceService.checkAccess(workspaceUuid, resourceId, userRequest);
    return new ResponseEntity<>(isValid, HttpStatus.OK);
  }

  @Override
  public ResponseEntity<Void> updateResourceProperties(
      UUID workspaceUuid, UUID resourceUuid, List<ApiProperty> properties) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    workspaceService.validateWorkspaceAndAction(
        userRequest, workspaceUuid, SamConstants.SamWorkspaceAction.WRITE);

    validatePropertiesUpdateRequestBody(properties);
    Map<String, String> propertiesMap = convertApiPropertyToMap(properties);
    ResourceValidationUtils.validateProperties(propertiesMap);

    resourceService.updateResourceProperties(workspaceUuid, resourceUuid, propertiesMap);
    return new ResponseEntity<>(HttpStatus.NO_CONTENT);
  }

  @Override
  public ResponseEntity<Void> deleteResourceProperties(
      UUID workspaceUuid, UUID resourceUuid, List<String> propertyKeys) {
    AuthenticatedUserRequest userRequest = getAuthenticatedInfo();
    validatePropertiesDeleteRequestBody(propertyKeys);
    workspaceService.validateWorkspaceAndAction(
        userRequest, workspaceUuid, SamConstants.SamWorkspaceAction.WRITE);
    resourceService.deleteResourceProperties(workspaceUuid, resourceUuid, propertyKeys);
    return new ResponseEntity<>(HttpStatus.NO_CONTENT);
  }

  // Convert a WsmResource into the API format for enumeration
  @VisibleForTesting
  public ApiResourceDescription makeApiResourceDescription(WsmResource wsmResource) {
    ApiResourceMetadata common = wsmResource.toApiMetadata();
    ApiResourceAttributesUnion union = wsmResource.toApiAttributesUnion();
    return new ApiResourceDescription().metadata(common).resourceAttributes(union);
  }
}

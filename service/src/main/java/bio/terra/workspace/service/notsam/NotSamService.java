package bio.terra.workspace.service.notsam;

import bio.terra.common.exception.ForbiddenException;
import bio.terra.common.tracing.OkHttpClientTracingInterceptor;
import bio.terra.workspace.app.configuration.external.SamConfiguration;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.iam.model.ControlledResourceIamRole;
import bio.terra.workspace.service.iam.model.RoleBinding;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.gcsbucket.ControlledGcsBucketResource;
import bio.terra.workspace.service.resource.controlled.model.AccessScopeType;
import bio.terra.workspace.service.resource.controlled.model.ControlledResource;
import bio.terra.workspace.service.resource.controlled.model.ManagedByType;
import bio.terra.workspace.service.resource.model.WsmResourceType;
import bio.terra.workspace.service.spice.SpiceService;
import bio.terra.workspace.service.workspace.GcpCloudContextService;
import io.opencensus.trace.Tracing;
import okhttp3.OkHttpClient;
import org.broadinstitute.dsde.workbench.client.sam.ApiClient;
import org.broadinstitute.dsde.workbench.client.sam.ApiException;
import org.broadinstitute.dsde.workbench.client.sam.api.UsersApi;
import org.broadinstitute.dsde.workbench.client.sam.model.UserStatusInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * NOTES:
 *
 * <ul>
 *   <le>User management remains in Sam in this prototype. We need more design in how we are
 *   handling users in general for Verily.</le> <le>Idea: read users from config (run only in Broad
 *   dev) Only new SAs will get put in the Spice proxy group, but those are the only ones we
 *   need</le> <le>Spice proxy group id == principal user id</le> <le>An optimization would be to
 *   cache the proxy group mapping so we are not hitting SpiceDB for that lookup</le> <le>Note:
 *   Admin permission is not yet implemented - it runs against Sam</le> <le>Applications are not yet
 *   implemented</le> <le>Private user cleanup is not needed in this scheme; not implemented
 *   either</le>
 * </ul>
 *
 * NEXT TO DO: createControlledResource TODO: Remove use of sync policies TODO: Turn off private
 * user cleanup
 */
@Component
public class NotSamService {
  private static final Logger logger = LoggerFactory.getLogger(NotSamService.class);

  private final SpiceService spiceService;
  private final UserManager userManager;
  private final AclManagerProject aclManagerProject;
  private final AclManagerBucket aclManagerBucket;
  private final GcpCloudContextService gcpCloudContextService;
  private final OkHttpClient commonHttpClient;
  private final SamConfiguration samConfig;

  @Autowired
  public NotSamService(
    SpiceService spiceService,
    UserManager userManager,
    AclManagerProject aclManagerProject,
    AclManagerBucket aclManagerBucket,
    GcpCloudContextService gcpCloudContextService,
    SamConfiguration samConfig) {
    this.spiceService = spiceService;
    this.userManager = userManager;
    this.aclManagerProject = aclManagerProject;
    this.aclManagerBucket = aclManagerBucket;
    this.gcpCloudContextService = gcpCloudContextService;
    this.commonHttpClient =
      new ApiClient()
        .getHttpClient()
        .newBuilder()
        .addInterceptor(new OkHttpClientTracingInterceptor(Tracing.getTracer()))
        .build();
    this.samConfig = samConfig;
  }

  public void initialize(String wsmSaEmail) {
    userManager.initializeProxyGroups();
    userManager.addWsmSa(wsmSaEmail);

    // TODO: Decide how to use watching
    // Start the watcher flight
    //launchWatcher();
  }

  /**
   * Create the first entry for workspace authorization checking: the owner proxy group gets owner
   * role on the workspace.
   *
   * @param userRequest user creating the workspace
   * @param workspaceId workspace id
   * @param authDomainList auth domain list - not supported yet
   */
  public void createWorkspaceAuthz(
      AuthenticatedUserRequest userRequest, UUID workspaceId, List<String> authDomainList) {
    if (authDomainList != null && authDomainList.size() != 0) {
      throw new RuntimeException("Auth domain groups are not supported in the proto yet");
    }

    String proxyGroupId = getProxyGroupIdFromUserRequest(userRequest);

    // Grant the creating user the owner role on the workspace
    spiceService.createRelationship(
        "proxy_group",
      proxyGroupId,
      "workspace",
      workspaceId.toString(),
      "owner",
      "membership");

    // Grant WSM the manager role on the workspace
    spiceService.createRelationship(
        "proxy_group",
        userManager.getWsmSaSubjectId(),
        "workspace",
        workspaceId.toString(),
        "manager",
        "membership");
  }

  public record WorkspaceAndRole(UUID workspaceId, WsmIamRole role) {}
  /**
   * @param userRequest user making the request
   * @param minimumRole minimum role user must have for workspace to be included in the return
   * @return list of workspace and associated role of the user
   */
  public List<WorkspaceAndRole> listWorkspacesAndRole(
      AuthenticatedUserRequest userRequest, WsmIamRole minimumRole) {
    String proxyGroupId = getProxyGroupIdFromUserRequest(userRequest);

    // Find all of the workspaces where this proxy group has a role
    List<SpiceService.SpiceRelationship> relationships =
        spiceService.readResourceRelationships(
            "workspace",
          null,
          null,
          "proxy_group",
          proxyGroupId,
          "membership");

    Map<String, WsmIamRole> workspaceRoleMap = new HashMap<>();

    for (var relationship : relationships) {
      WsmIamRole relationshipRole = WsmIamRole.fromSam(relationship.resourceRelation());
      // Skip unknown relationships or ones less than the minimum role
      if (relationshipRole == null || !minimumRole.roleAtLeastAsHighAs(relationshipRole)) {
        continue;
      }

      WsmIamRole currentRole = workspaceRoleMap.get(relationship.resourceId());
      // The scheme in WsmIamRole is very awkward for doing a simple comparison, but
      // I think this hack will work (at least as high && not the same)
      if (currentRole == null
          || (relationshipRole.roleAtLeastAsHighAs(currentRole)
              && relationshipRole != currentRole)) {
        workspaceRoleMap.put(relationship.resourceId(), relationshipRole);
      }
    }

    return workspaceRoleMap.entrySet().stream()
        .map(e -> new WorkspaceAndRole(UUID.fromString(e.getKey()), e.getValue()))
        .toList();
  }

  /**
   * Delete the authorization information about a workspace Note this does not do any access control
   * checking.
   *
   * @param workspaceId workspace to delete
   */
  public void deleteWorkspaceAuthz(UUID workspaceId) {
    // TODO: delete all of the child resource authz
    spiceService.deleteResourceRelationships(
        "workspace", workspaceId.toString(), null, null, null, null);
  }

  /**
   * Grant a principal a role on a workspace
   * NOTE: we rely on upper layers to trigger the ACL updates
   *
   * @param workspaceId workspace to grant to
   * @param userRequest - authenticated user; must have share_policy_<role>
   * @param role role to grant
   * @param granteeEmail grantee
   */
  public void grantWorkspaceRole(
      UUID workspaceId,
      AuthenticatedUserRequest userRequest,
      WsmIamRole role,
      String granteeEmail) {
    // First we check that the grantor has the share permission allowing the grant
    String grantorSubjectId = getSubjectIdFromUserRequest(userRequest);
    checkCanGrant(workspaceId, grantorSubjectId, role);

    // Second, setup and perform the grant
    // Make sure we grant to the proxy group, regardless of who in the proxy group made the call
    String granteeSubjectId = getSubjectIdFromEmail(granteeEmail);
    String proxyGroupId = getProxyGroupIdFromSubjectId(granteeSubjectId);

    spiceService.createRelationship(
      "proxy_group",
      proxyGroupId,
      "workspace",
      workspaceId.toString(),
      role.toSamRole(),
      "membership");
  }

  public boolean isAclRole(WsmIamRole role) {
    return aclManagerProject.isAclRole(role);
  }

  /**
   * Revoke a role on a workspace from a principal
   *
   * @param workspaceId workspace to revoke from
   * @param userRequest - authenticated user; must have share_policy_<role>
   * @param role role to grant
   * @param granteeEmail grantee
   */
  public void revokeWorkspaceRole(
      UUID workspaceId,
      AuthenticatedUserRequest userRequest,
      WsmIamRole role,
      String granteeEmail) {
    // First we check that the grantor has the share permission allowing the grant
    String grantorSubjectId = getSubjectIdFromUserRequest(userRequest);
    checkCanGrant(workspaceId, grantorSubjectId, role);

    // Second, setup and perform the revoke
    String granteeSubjectId = getSubjectIdFromEmail(granteeEmail);
    String proxyGroupId = getProxyGroupIdFromSubjectId(granteeSubjectId);
    spiceService.deleteRelationship(
      "proxy_group",
      proxyGroupId,
      "workspace",
      workspaceId.toString(),
      role.toSamRole(),
      "membership");
  }

  /**
   * List role bindings has a specific permission model: - if you have read_policy_owner, you get
   * the owners and yourself - if you have read_policies, you get everything TODO: Question - can a
   * user get their own role bindings via this call?
   *
   * @param workspaceId workspace to list roles on
   * @param userRequest user doing the listing
   * @return list of role bindings; may be empty
   */
  public List<RoleBinding> listRoleBindings(
      UUID workspaceId, AuthenticatedUserRequest userRequest) {
    String subjectId = getProxyGroupIdFromUserRequest(userRequest);
    return listRoleBindings(workspaceId, subjectId);
  }

  // This is a permission check that filters what roles the subject is allowed to see
  private List<WsmIamRole> visibleRolesForSubject(UUID workspaceId, String subjectId) {

    // If the subject can read all policies, return that
    if (spiceService.checkPermission(
      subjectId, "workspace", workspaceId.toString(), "read_policies")) {
      return List.of(WsmIamRole.OWNER, WsmIamRole.WRITER, WsmIamRole.READER, WsmIamRole.DISCOVERER);
    }

    // If the subject can just read owner, return that
    if (spiceService.checkPermission(
      subjectId, "workspace", workspaceId.toString(), "read_policy_owner")) {
      return List.of(WsmIamRole.OWNER);
    }

    return Collections.emptyList();
  }

  public List<RoleBinding> listRoleBindings(UUID workspaceId, String subjectId) {
    List<RoleBinding> resultList = new ArrayList<>();
    for (WsmIamRole role : visibleRolesForSubject(workspaceId, subjectId)) {
      resultList.add(getRoleSubjects(workspaceId, role));
    }
    return resultList;
  }

  private RoleBinding getRoleSubjects(UUID workspaceId, WsmIamRole role) {
    Set<String> subjects =
        spiceService.lookupSubjects(
            "workspace",
          workspaceId.toString(),
          role.toSamRole(),
          "user",
          null);
    return RoleBinding.builder()
        .role(role)
        .users(subjects.stream().map(userManager::getUserEmail).toList())
        .build();
  }

  // I made this call more specific: it only does workspace roles. That is the only use case in WSM.
  public List<WsmIamRole> listRequesterRoles(
      String workspaceId, AuthenticatedUserRequest userRequest) {
    String subjectId = getProxyGroupIdFromUserRequest(userRequest);

    List<WsmIamRole> resultList = new ArrayList<>();

    if (doesSubjectHaveRole(workspaceId, subjectId, WsmIamRole.OWNER)) {
      resultList.add(WsmIamRole.OWNER);
    }
    if (doesSubjectHaveRole(workspaceId, subjectId, WsmIamRole.WRITER)) {
      resultList.add(WsmIamRole.WRITER);
    }
    if (doesSubjectHaveRole(workspaceId, subjectId, WsmIamRole.READER)) {
      resultList.add(WsmIamRole.READER);
    }
    if (doesSubjectHaveRole(workspaceId, subjectId, WsmIamRole.DISCOVERER)) {
      resultList.add(WsmIamRole.DISCOVERER);
    }
    return resultList;
  }

  private boolean doesSubjectHaveRole(String workspaceId, String subjectId, WsmIamRole role) {
    Set<String> subjects =
        spiceService.lookupSubjects("workspace", workspaceId, role.toSamRole(), "user", null);
    return subjects.contains(subjectId);
  }

  // TODO: this is the wrong interface. What the caller really wants to know is if the user has a direct
  //  role on the workspace. The NotSam implementation returns either a list of one (the requesting user)
  //  or an empty list.
  //  Also, since we have not implemented groups, we can naively do the subject lookup.
  public List<String> listUsersWithWorkspaceRole(UUID workspaceId, WsmIamRole role, AuthenticatedUserRequest userRequest) {
    List<String> userList = new ArrayList<>();

    String subjectId = getSubjectIdFromUserRequest(userRequest);
    List<WsmIamRole> visibleRoles = visibleRolesForSubject(workspaceId, subjectId);
    if (visibleRoles.contains(role)) {
      Set<String> subjects =
        spiceService.lookupSubjects(
          "workspace",
          workspaceId.toString(),
          role.toSamRole(),
          "user",
          null);

      for (String oneSubjectId : subjects) {
        userList.add(userManager.getUserEmail(oneSubjectId));
      }
    }
    return userList;
  }

  public record ResourceRoleBinding(ControlledResourceIamRole role, List<String> users) {}
  /**
   * NOTE: this does not do any permission filtering, since it is only used to construct
   * the IAM roles on behalf of IAM; that is, not running as a user.
   *
   * @param resourceId controlled resource
   * @return list of role bindings
   */
  public List<ResourceRoleBinding> listResourceRoleBindings(UUID resourceId) {
    List<ResourceRoleBinding> resultList = new ArrayList<>();
    resultList.add(getResourceRoleBinding(resourceId, ControlledResourceIamRole.READER));
    resultList.add(getResourceRoleBinding(resourceId, ControlledResourceIamRole.WRITER));
    resultList.add(getResourceRoleBinding(resourceId, ControlledResourceIamRole.EDITOR));
    return resultList;
  }

  private ResourceRoleBinding getResourceRoleBinding(UUID resourceId, ControlledResourceIamRole role) {
    String permission =
      switch (role) {
        case READER -> "read";
        case WRITER -> "write";
        case EDITOR -> "edit";
        default -> null;
      };
    if (permission == null) {
      return null;
    }

    Set<String> subjects =
      spiceService.lookupSubjects(
        "controlled_user_shared_resource",
        resourceId.toString(),
        permission,
        "user",
        null);

    List<String> users = subjects.stream().map(userManager::getUserEmail).toList();
    return new ResourceRoleBinding(role, users);
  }

  /**
   * Check that a grantor has the right share permission to grant a role. This check is used for
   * both grant and revoke operations.
   *
   * @param workspaceId workspace of interest
   * @param grantorSubjectId subject id of the proposed grantor
   * @param role proposed role to grant/revoke
   */
  private void checkCanGrant(UUID workspaceId, String grantorSubjectId, WsmIamRole role) {
    // Compute the share policy
    // TODO: this would go in WsmIamRole in a real system
    String sharePolicy =
        switch (role) {
          case READER -> "share_policy_reader";
          case WRITER -> "share_policy_writer";
          case OWNER -> "share_policy_owner";
          case MANAGER -> null;
          case DISCOVERER -> "share_policy_discoverer";
          case APPLICATION -> null;
        };
    if (sharePolicy == null) {
      throw new IllegalArgumentException(role + " cannot be granted");
    }
    if (!isAuthorized(grantorSubjectId, "workspace", workspaceId.toString(), sharePolicy)) {
      throw new ForbiddenException(
          String.format("Permission %s is required to grant %s on a workspace", sharePolicy, role));
    }
  }

  /**
   * We require the subjectId from the userRequest
   *
   * @param userRequest user request with proper subject id
   * @param iamResourceType WSM resource type
   * @param resourceId resource id
   * @param action permission to test
   * @return boolean
   */
  public boolean isAuthorized(
      AuthenticatedUserRequest userRequest,
      String iamResourceType,
      String resourceId,
      String action) {
    String subjectId = getSubjectIdFromUserRequest(userRequest);
    return isAuthorized(subjectId, iamResourceType, resourceId, action);
  }

  /**
   * First, make sure the caller has `read_policies` on the resource. If so, then they are allowed
   * to do the second check. For now, we just lookup the
   *
   * @param iamResourceType WSM resource type
   * @param resourceId resource id
   * @param action permission to test
   * @param userToCheck userEmail to test
   * @param userRequest requesting user
   * @return boolean
   */
  public boolean isOtherUserAuthorized(
      String iamResourceType,
      String resourceId,
      String action,
      String userToCheck,
      AuthenticatedUserRequest userRequest) {
    String checkerSubjectId = getSubjectIdFromUserRequest(userRequest);
    if (!isAuthorized(checkerSubjectId, iamResourceType, resourceId, "read_policies")) {
      throw new ForbiddenException(
          "read_policies permission is required to check another user's access");
    }

    String userSubjectId = getSubjectIdFromEmail(userToCheck);
    return isAuthorized(userSubjectId, iamResourceType, resourceId, action);
  }

  /** Common worker for isAuthorized variants */
  private boolean isAuthorized(
      String subjectId, String iamResourceType, String resourceId, String action) {

    // TODO: implement spend profiles. For new we "hard mock" all spend profile checks
    if (iamResourceType.equals("spend-profile")) {
      return true;
    }

    return spiceService.checkPermission(subjectId, iamResourceType, resourceId, action);
  }

  /**
   * Create the authz setup for a controlled resource. NOTE: application is not implemented, so we
   * always create resources giving the requesting user editor permission.
   *
   * @param resource controlled resource object
   * @param userRequest user making the create request
   */
  public void createControlledResourceAuthz(
      ControlledResource resource, AuthenticatedUserRequest userRequest) {
    String workspaceId = resource.getWorkspaceId().toString();
    String resourceId = resource.getResourceId().toString();

    if (resource.getManagedBy() == ManagedByType.MANAGED_BY_APPLICATION) {
      throw new RuntimeException("Application is not implemented");
    }

    if (resource.getAccessScope() == AccessScopeType.ACCESS_SCOPE_SHARED) {
      spiceService.createRelationship(
          "workspace",
          workspaceId,
          "controlled_user_shared_resource",
          resourceId,
          "parent_workspace",
          null);
    } else {
      String proxyGroupId = getProxyGroupIdFromUserRequest(userRequest);
      spiceService.createRelationship(
          "workspace",
          workspaceId,
          "controlled_user_private_resource",
          resourceId,
          "parent_workspace",
          null);

      spiceService.createRelationship(
          "proxy_group",
          proxyGroupId,
          "controlled_user_private_resource",
          resourceId,
          "editor",
          "membership");
    }
  }

  // We assume upper layers have checked that the caller is allowed to delete the resource
  public void deleteControlledResourceAuthz(ControlledResource resource) {
    if (resource.getManagedBy() == ManagedByType.MANAGED_BY_APPLICATION) {
      throw new RuntimeException("Application is not implemented");
    }

    String resourceType =
        (resource.getAccessScope() == AccessScopeType.ACCESS_SCOPE_SHARED
            ? "controlled_user_shared_resource"
            : "controlled_user_private_resource");

    spiceService.deleteResourceRelationships(
        resourceType, resource.getResourceId().toString(), null, null, null, null);
  }

  public void getOrCreatePetSaEmail(AuthenticatedUserRequest userRequest, String petSaEmail) {
    String proxyGroupId = getProxyGroupIdFromUserRequest(userRequest);
    userManager.addSaToProxyGroup(proxyGroupId, petSaEmail);
  }

  /**
   * Given an AuthenticatedUserRequest with an email in it, find our subject id.
   *
   * @param userRequest user request
   * @return subject id
   */
  private String getSubjectIdFromUserRequest(AuthenticatedUserRequest userRequest) {
    String email =
      userRequest.getEmail() == null
        ? getEmailFromToken(userRequest.getRequiredToken())
        : userRequest.getEmail();
    return getSubjectIdFromEmail(email);
  }

  private String getSubjectIdFromEmail(String email) {
    if (email == null) {
      throw new IllegalArgumentException("Null email in user request");
    }
    String subjectId = userManager.getUserSubjectId(email);
    if (subjectId == null) {
      throw new IllegalArgumentException("User not in the system: {}" + email);
    }
    return subjectId;
  }

  /**
   * Retrieve the proxy group id given a user request. This finds the proxy group id (equivalent to
   * the primary user id) from the user request. There should be exactly one.
   *
   * @param userRequest authenticated identity
   * @return proxy group id
   */
  private String getProxyGroupIdFromUserRequest(AuthenticatedUserRequest userRequest) {
    String subjectId = getSubjectIdFromUserRequest(userRequest);
    return getProxyGroupIdFromSubjectId(subjectId);
  }

  private String getProxyGroupIdFromSubjectId(String subjectId) {
    // Find proxy groups with the subject id as a member
    List<String> proxyGroupList =
        spiceService.lookupResources("user", subjectId, "proxy_group", "membership");

    if (proxyGroupList.size() != 1) {
      throw new RuntimeException(
          String.format("Did not find a proxy group for subjectId: %s", subjectId));
    }

    return proxyGroupList.get(0);
  }

  public void updateWorkspaceAcl(UUID workspaceId, @Nullable List<ControlledResource> controlledResources) {
    // If we have no cloud context, we have nothing to do
    Optional<String> maybeProjectId = gcpCloudContextService.getGcpProject(workspaceId);
    if (maybeProjectId.isEmpty()) {
      return;
    }
    String projectId = maybeProjectId.get();
    updateProjectAcl(workspaceId, projectId);

    if (controlledResources != null) {
      for (ControlledResource resource : controlledResources) {
        // TODO: We are only dealing with shared buckets for the prototype
        if (resource.getResourceType() != WsmResourceType.CONTROLLED_GCP_GCS_BUCKET
        && resource.getAccessScope() != AccessScopeType.ACCESS_SCOPE_SHARED) {
          continue;
        }

        updateBucketAcl(resource.castByEnum(WsmResourceType.CONTROLLED_GCP_GCS_BUCKET), projectId);
      }
    }
  }

  public void updateBucketAcl(ControlledGcsBucketResource resource, String projectId) {
    List<ResourceRoleBinding> roleBindings = listResourceRoleBindings(resource.getResourceId());
    aclManagerBucket.updateBucketAcl(resource, projectId, roleBindings);
  }

  public void updateProjectAcl(UUID workspaceId, String projectId) {
    List<RoleBinding> roleBindings = listRoleBindings(workspaceId, userManager.getWsmSaSubjectId());
    aclManagerProject.updateProjectAcl(projectId, roleBindings);
  }

  public String getEmailFromToken(String accessToken) {
    // OkHttpClient objects manage their own thread pools, so it's much more performant to share one
    // across requests.
    ApiClient apiClient =
      new ApiClient().setHttpClient(commonHttpClient).setBasePath(samConfig.getBasePath());
      apiClient.setAccessToken(accessToken);
    UsersApi usersApi = new UsersApi(apiClient);
    try {
      UserStatusInfo userStatusInfo = usersApi.getUserStatusInfo();
      return userStatusInfo.getUserEmail();
    } catch (ApiException e) {
      throw new RuntimeException(e);
    }
  }
}

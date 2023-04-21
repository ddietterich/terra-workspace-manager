package bio.terra.workspace.service.iam;

import bio.terra.cloudres.google.iam.ServiceAccountName;
import bio.terra.common.exception.ForbiddenException;
import bio.terra.common.exception.InternalServerErrorException;
import bio.terra.common.sam.SamRetry;
import bio.terra.common.sam.exception.SamExceptionFactory;
import bio.terra.common.tracing.OkHttpClientTracingInterceptor;
import bio.terra.workspace.app.configuration.external.SamConfiguration;
import bio.terra.workspace.db.WorkspaceDao;
import bio.terra.workspace.service.iam.model.ControlledResourceIamRole;
import bio.terra.workspace.service.iam.model.RoleBinding;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import bio.terra.workspace.service.notsam.NotSamService;
import bio.terra.workspace.service.notsam.UserManager;
import bio.terra.workspace.service.resource.controlled.model.ControlledResource;
import bio.terra.workspace.service.workspace.model.Workspace;
import bio.terra.workspace.service.workspace.model.WorkspaceDescription;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import io.opencensus.contrib.spring.aop.Traced;
import io.opencensus.trace.Tracing;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import okhttp3.OkHttpClient;
import org.broadinstitute.dsde.workbench.client.sam.ApiClient;
import org.broadinstitute.dsde.workbench.client.sam.ApiException;
import org.broadinstitute.dsde.workbench.client.sam.api.AdminApi;
import org.broadinstitute.dsde.workbench.client.sam.api.AzureApi;
import org.broadinstitute.dsde.workbench.client.sam.api.GoogleApi;
import org.broadinstitute.dsde.workbench.client.sam.api.ResourcesApi;
import org.broadinstitute.dsde.workbench.client.sam.api.StatusApi;
import org.broadinstitute.dsde.workbench.client.sam.api.UsersApi;
import org.broadinstitute.dsde.workbench.client.sam.model.AccessPolicyResponseEntryV2;
import org.broadinstitute.dsde.workbench.client.sam.model.GetOrCreatePetManagedIdentityRequest;
import org.broadinstitute.dsde.workbench.client.sam.model.SystemStatus;
import org.broadinstitute.dsde.workbench.client.sam.model.UserIdInfo;
import org.broadinstitute.dsde.workbench.client.sam.model.UserStatusInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

/**
 * SamService encapsulates logic for interacting with Sam. HTTP Statuses returned by Sam are
 * interpreted by the functions in this class.
 *
 * <p>This class is used both by Flights and outside of Flights. Flights need the
 * InterruptedExceptions to be thrown. Outside of flights, use the SamRethrow.onInterrupted. See
 * comment there for more detail.
 */
@Component
public class SamService {

  private static final Set<String> SAM_OAUTH_SCOPES = ImmutableSet.of("openid", "email", "profile");
  private static final List<String> PET_SA_OAUTH_SCOPES =
      ImmutableList.of(
          "openid", "email", "profile", "https://www.googleapis.com/auth/cloud-platform");
  private static final Logger logger = LoggerFactory.getLogger(SamService.class);
  private final SamConfiguration samConfig;
  private final OkHttpClient commonHttpClient;

  private final WorkspaceDao workspaceDao;
  private final NotSamService notSamService;
  private final UserManager userManager;
  private boolean wsmServiceAccountInitialized;

  @Autowired
  public SamService(
      SamConfiguration samConfig,
      WorkspaceDao workspaceDao,
      NotSamService notSamService,
      UserManager userManager) {
    this.samConfig = samConfig;
    this.wsmServiceAccountInitialized = false;
    this.commonHttpClient =
        new ApiClient()
            .getHttpClient()
            .newBuilder()
            .addInterceptor(new OkHttpClientTracingInterceptor(Tracing.getTracer()))
            .build();
    this.workspaceDao = workspaceDao;
    this.notSamService = notSamService;
    this.userManager = userManager;
  }

  private ApiClient getApiClient(String accessToken) {
    // OkHttpClient objects manage their own thread pools, so it's much more performant to share one
    // across requests.
    ApiClient apiClient =
        new ApiClient().setHttpClient(commonHttpClient).setBasePath(samConfig.getBasePath());
    apiClient.setAccessToken(accessToken);
    return apiClient;
  }

  private ResourcesApi samResourcesApi(String accessToken) {
    return new ResourcesApi(getApiClient(accessToken));
  }

  private GoogleApi samGoogleApi(String accessToken) {
    return new GoogleApi(getApiClient(accessToken));
  }

  @VisibleForTesting
  public UsersApi samUsersApi(String accessToken) {
    return new UsersApi(getApiClient(accessToken));
  }

  @VisibleForTesting
  public AzureApi samAzureApi(String accessToken) {
    return new AzureApi(getApiClient(accessToken));
  }

  public AdminApi samAdminApi(String accessToken) {
    return new AdminApi(getApiClient(accessToken));
  }

  @Traced
  private boolean isAdmin(AuthenticatedUserRequest userRequest) throws InterruptedException {
    try {
      // If the user can successfully call sam admin api, the user has terra level admin access.
      SamRetry.retry(
          () ->
              samAdminApi(userRequest.getRequiredToken())
                  .adminGetUserByEmail(getUserEmailFromSam(userRequest)));
      return true;
    } catch (ApiException apiException) {
      logger.info(
          "Error checking admin permission in Sam. This is expected if requester is not SAM admin.",
          apiException);
      return false;
    }
  }

  @VisibleForTesting
  public String getWsmServiceAccountToken() {
    try {
      GoogleCredentials creds =
          GoogleCredentials.getApplicationDefault().createScoped(SAM_OAUTH_SCOPES);
      creds.refreshIfExpired();
      return creds.getAccessToken().getTokenValue();
    } catch (IOException e) {
      throw new InternalServerErrorException("Internal server error retrieving WSM credentials", e);
    }
  }

  /**
   * Fetch the email associated with user credentials directly from Sam. Call this method outside a
   * flight as we don't need to retry when `InterruptException` happens outside a flight.
   */
  public String getUserEmailFromSamAndRethrowOnInterrupt(AuthenticatedUserRequest userRequest) {
    return SamRethrow.onInterrupted(
        () -> getUserEmailFromSam(userRequest), "Get user email from SAM");
  }

  /**
   * Fetch the email associated with user credentials directly from Sam. Unlike {@code
   * getRequestUserEmail}, this will always call Sam to fetch an email and will never read it from
   * the AuthenticatedUserRequest. This is important for calls made by pet service accounts, which
   * will have a pet email in the AuthenticatedUserRequest, but Sam will return the owner's email.
   */
  public String getUserEmailFromSam(AuthenticatedUserRequest userRequest)
      throws InterruptedException {
    return getUserStatusInfo(userRequest).getUserEmail();
  }

  /** Fetch the user status info associated with the user credentials directly from Sam. */
  public UserStatusInfo getUserStatusInfo(AuthenticatedUserRequest userRequest)
      throws InterruptedException {
    UsersApi usersApi = samUsersApi(userRequest.getRequiredToken());
    try {
      return SamRetry.retry(usersApi::getUserStatusInfo);
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create("Error getting user status info from Sam", apiException);
    }
  }

  /** Fetch a user-assigned managed identity from Sam by user email with WSM credentials. */
  public String getOrCreateUserManagedIdentityForUser(
      String userEmail, String subscriptionId, String tenantId, String managedResourceGroupId)
      throws InterruptedException {
    AzureApi azureApi = samAzureApi(getWsmServiceAccountToken());

    GetOrCreatePetManagedIdentityRequest request =
        new GetOrCreatePetManagedIdentityRequest()
            .subscriptionId(subscriptionId)
            .tenantId(tenantId)
            .managedResourceGroupName(managedResourceGroupId);
    try {
      return SamRetry.retry(
          () -> azureApi.getPetManagedIdentityForUser(userEmail.toLowerCase(), request));
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create(
          "Error getting user assigned managed identity from Sam", apiException);
    }
  }

  /**
   * Gets proxy group email.
   *
   * <p>This takes in userEmail instead of AuthenticatedUserRequest because of
   * WorkspaceService.removeWorkspaceRoleFromUser(). When User A removes User B from workspace, we
   * want to get B's proxy group, not A's.
   */
  public String getProxyGroupEmail(String userEmail, String token) throws InterruptedException {
    GoogleApi googleApi = samGoogleApi(token);
    try {
      return SamRetry.retry(() -> googleApi.getProxyGroup(userEmail));
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create("Error getting proxy group from Sam", apiException);
    }
  }

  @VisibleForTesting
  public boolean wsmServiceAccountRegistered(UsersApi usersApi) throws InterruptedException {
    try {
      // getUserStatusInfo throws a 404 if the calling user is not registered, which will happen
      // the first time WSM is run in each environment.
      SamRetry.retry(usersApi::getUserStatusInfo);
      logger.info("WSM service account already registered in Sam");
      return true;
    } catch (ApiException apiException) {
      if (apiException.getCode() == HttpStatus.NOT_FOUND.value()) {
        logger.info(
            "Sam error was NOT_FOUND when checking user registration. This means the "
                + " user is not registered but is not an exception. Returning false.");
        return false;
      } else {
        throw SamExceptionFactory.create("Error checking user status in Sam", apiException);
      }
    }
  }

  /**
   * Wrapper around the Sam client to create a workspace resource in Sam.
   *
   * <p>This creates a workspace with the provided ID and requesting user as the sole Owner. Empty
   * reader and writer policies are also created. Errors from the Sam client will be thrown as Sam
   * specific exception types.
   */
  @Traced
  public void createWorkspaceWithDefaults(
      AuthenticatedUserRequest userRequest, UUID uuid, List<String> authDomainList)
      throws InterruptedException {

    notSamService.createWorkspaceAuthz(userRequest, uuid, authDomainList);
  }

  /**
   * List all workspace IDs in Sam this user has access to. Note that in environments shared with
   * Rawls, some of these workspaces will be Rawls managed and WSM will not know about them.
   *
   * <p>Additionally, Rawls may create additional roles that WSM does not know about. Those roles
   * will be ignored here.
   *
   * @return map from workspace ID to highest SAM role
   */
  @Traced
  public Map<UUID, WorkspaceDescription> listWorkspaceIdsAndHighestRoles(
      AuthenticatedUserRequest userRequest, WsmIamRole minimumHighestRoleFromRequest)
      throws InterruptedException {
    Map<UUID, WorkspaceDescription> result = new HashMap<>();

    List<NotSamService.WorkspaceAndRole> workspaceAndRoleList =
        notSamService.listWorkspacesAndRole(userRequest, minimumHighestRoleFromRequest);

    for (var workspaceAndRole : workspaceAndRoleList) {
      Optional<Workspace> workspaceOptional =
          workspaceDao.getWorkspaceIfExists(workspaceAndRole.workspaceId());
      if (workspaceOptional.isEmpty()) {
        continue;
      }

      result.put(
          workspaceAndRole.workspaceId(),
          new WorkspaceDescription(
              workspaceOptional.get(),
              workspaceAndRole.role(),
              new ArrayList<String>())); // empty list of missing auth domains
    }

    return result;
  }

  @Traced
  public void deleteWorkspace(AuthenticatedUserRequest userRequest, UUID uuid)
      throws InterruptedException {

    notSamService.deleteWorkspaceAuthz(uuid);
  }

  @Traced
  public List<String> listResourceActions(
      AuthenticatedUserRequest userRequest, String resourceType, String resourceId)
      throws InterruptedException {
    // TODO: Azure only method - skip for now
    String authToken = userRequest.getRequiredToken();
    ResourcesApi resourceApi = samResourcesApi(authToken);
    try {
      return SamRetry.retry(() -> resourceApi.resourceActionsV2(resourceType, resourceId));
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create("Error listing resources actions in Sam", apiException);
    }
  }

  @Traced
  public boolean isAuthorized(
      AuthenticatedUserRequest userRequest,
      String iamResourceType,
      String resourceId,
      String action)
      throws InterruptedException {
    return notSamService.isAuthorized(userRequest, iamResourceType, resourceId, action);
  }

  /**
   * Check whether a user may perform an action on a Sam resource. Unlike {@code isAuthorized}, this
   * method does not require that the calling user and the authenticating user are the same - e.g.
   * user A may ask Sam whether user B has permission to perform an action.
   *
   * @param iamResourceType The type of the Sam resource to check
   * @param resourceId The ID of the Sam resource to check
   * @param action The action we're querying Sam for
   * @param userToCheck The email of the principle whose permission we are checking
   * @param userRequest Credentials for the call to Sam. These do not need to be from the same user
   *     as userToCheck.
   * @return True if userToCheck may perform the specified action on the specified resource. False
   *     otherwise.
   */
  @Traced
  public boolean userIsAuthorized(
      String iamResourceType,
      String resourceId,
      String action,
      String userToCheck,
      AuthenticatedUserRequest userRequest)
      throws InterruptedException {
    return notSamService.isOtherUserAuthorized(
        iamResourceType, resourceId, action, userToCheck, userRequest);
  }

  /**
   * Wrapper around {@code userIsAuthorized} which checks authorization using the WSM Service
   * Account's credentials rather than an end user's credentials. This should only be used when user
   * credentials are not available, as WSM's SA has permission to read all workspaces and resources.
   */
  public boolean checkAuthAsWsmSa(
      String iamResourceType, String resourceId, String action, String userToCheck)
      throws InterruptedException {
    // TODO: this is part of the private resource cleanup path, so no NotSam support

    String wsmSaToken = getWsmServiceAccountToken();
    AuthenticatedUserRequest wsmSaRequest =
        new AuthenticatedUserRequest().token(Optional.of(wsmSaToken));
    return userIsAuthorized(iamResourceType, resourceId, action, userToCheck, wsmSaRequest);
  }

  /**
   * Wrapper around isAuthorized which throws an appropriate exception if a user does not have
   * access to a resource. The wrapped call will perform a check for the appropriate permission in
   * Sam. This call answers the question "does user X have permission to do action Y on resource Z".
   *
   * @param userRequest Credentials of the user whose permissions are being checked
   * @param type The Sam type of the workspace/resource being checked
   * @param uuid The ID of the resource being checked
   * @param action The action being checked on the resource
   */
  @Traced
  public void checkAuthz(
      AuthenticatedUserRequest userRequest, String type, String uuid, String action)
      throws InterruptedException {

    boolean isAuthorized = notSamService.isAuthorized(userRequest, type, uuid, action);
    String userEmail = userRequest.getEmail();
    if (!isAuthorized) {
      throw new ForbiddenException(
          String.format(
              "User %s is not authorized to perform action %s on %s %s",
              userEmail, action, type, uuid));
    } else {
      logger.info("User {} is authorized to {} {} {}", userEmail, action, type, uuid);
    }
  }

  /**
   * Wrapper around isAdmin which throws an appropriate exception if a user does not have admin
   * access.
   *
   * @param userRequest Credentials of the user whose permissions are being checked
   */
  @Traced
  public void checkAdminAuthz(AuthenticatedUserRequest userRequest) throws InterruptedException {
    boolean isAuthorized = isAdmin(userRequest);
    final String userEmail = getUserEmailFromSam(userRequest);
    if (!isAuthorized)
      throw new ForbiddenException(
          String.format("User %s is not authorized to perform admin action", userEmail));
    else logger.info("User {} is an authorized admin", userEmail);
  }

  /**
   * Wrapper around Sam client to grant a role to the provided user.
   *
   * <p>This operation is only available to MC_WORKSPACE stage workspaces, as Rawls manages
   * permissions directly on other workspaces.
   *
   * @param workspaceUuid The workspace this operation takes place in
   * @param userRequest Credentials of the user requesting this operation. Only owners have
   *     permission to modify roles in a workspace.
   * @param role The role being granted.
   * @param email The user being granted a role.
   */
  @Traced
  public void grantWorkspaceRole(
      UUID workspaceUuid, AuthenticatedUserRequest userRequest, WsmIamRole role, String email)
      throws InterruptedException {

    notSamService.grantWorkspaceRole(workspaceUuid, userRequest, role, email);
  }

  /**
   * Wrapper around Sam client to remove a role from the provided user.
   *
   * <p>This operation is only available to MC_WORKSPACE stage workspaces, as Rawls manages
   * permissions directly on other workspaces. Trying to remove a role that a user does not have
   * will succeed, though Sam will error if the email is not a registered user.
   */
  @Traced
  public void removeWorkspaceRole(
      UUID workspaceUuid, AuthenticatedUserRequest userRequest, WsmIamRole role, String email)
      throws InterruptedException {

    notSamService.revokeWorkspaceRole(workspaceUuid, userRequest, role, email);
  }

  /**
   * Wrapper around the Sam client to remove a role from the provided user on a controlled resource.
   *
   * <p>Similar to {@removeWorkspaceRole}, but for controlled resources. This should only be
   * necessary for private resources, as users do not have individual roles on shared resources.
   *
   * <p>This call to Sam is made as the WSM SA, as users do not have permission to directly modify
   * IAM on resources.
   *
   * @param resource The resource to remove a role from
   * @param role The role to remove
   * @param email Email identifier of the user whose role is being removed.
   */
  @Traced
  public void removeResourceRole(
      ControlledResource resource, ControlledResourceIamRole role, String email)
      throws InterruptedException {
    // TODO: When using NotSam, we do not need to manage revoking on private resources
    //  as we can restrict private resources by auth domains and by membership in the
    //  workspace.
    try {
      ResourcesApi wsmSaResourceApi = samResourcesApi(getWsmServiceAccountToken());
      SamRetry.retry(
          () ->
              wsmSaResourceApi.removeUserFromPolicyV2(
                  resource.getCategory().getSamResourceName(),
                  resource.getResourceId().toString(),
                  role.toSamRole(),
                  email));
      logger.info(
          "Removed role {} from user {} on resource {}",
          role.toSamRole(),
          email,
          resource.getResourceId());
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create("Sam error removing resource role in Sam", apiException);
    }
  }

  /**
   * Wrapper around the Sam client to restore a role to a user on a controlled resource. This is
   * only exposed to support undoing Stairway transactions which revoke access. It should not be
   * called otherwise.
   *
   * <p>This call to Sam is made as the WSM SA, as users do not have permission to directly modify
   * IAM on resources.
   *
   * @param resource The resource to restore a role to
   * @param role The role to restore
   * @param email Email identifier of the user whose role is being restored.
   */
  @Traced
  public void restoreResourceRole(
      ControlledResource resource, ControlledResourceIamRole role, String email)
      throws InterruptedException {

    try {
      ResourcesApi wsmSaResourceApi = samResourcesApi(getWsmServiceAccountToken());
      SamRetry.retry(
          () ->
              wsmSaResourceApi.addUserToPolicyV2(
                  resource.getCategory().getSamResourceName(),
                  resource.getResourceId().toString(),
                  role.toSamRole(),
                  email,
                  /* body = */ null));
      logger.info(
          "Restored role {} to user {} on resource {}",
          role.toSamRole(),
          email,
          resource.getResourceId());
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create("Sam error restoring resource role in Sam", apiException);
    }
  }

  /**
   * Wrapper around Sam client to retrieve the full current permissions model of a workspace.
   *
   * <p>This operation is only available to MC_WORKSPACE stage workspaces, as Rawls manages
   * permissions directly on other workspaces.
   */
  @Traced
  public List<RoleBinding> listRoleBindings(
      UUID workspaceUuid, AuthenticatedUserRequest userRequest) throws InterruptedException {

    return notSamService.listRoleBindings(workspaceUuid, userRequest);
  }

  /** Wrapper around Sam client to fetch the list of users with a specific role in a workspace. */
  // TODO: this is the wrong interface. What we really want is to know if the user has a direct
  //  role on the workspace. So in a not-prototype, we could make this much better.
  @Traced
  public List<String> listUsersWithWorkspaceRole(
      UUID workspaceUuid, WsmIamRole role, AuthenticatedUserRequest userRequest) {
    return notSamService.listUsersWithWorkspaceRole(workspaceUuid, role, userRequest);
  }

  // Add code to retrieve and dump the role assignments for WSM controlled resources
  // for debugging. No permission check outside of Sam.
  public void dumpRoleBindings(String samResourceType, String resourceId, String token) {
    logger.debug("DUMP ROLE BINDING - resourceType {} resourceId {}", samResourceType, resourceId);

    ResourcesApi resourceApi = samResourcesApi(token);
    try {
      List<AccessPolicyResponseEntryV2> samResult =
          SamRetry.retry(() -> resourceApi.listResourcePoliciesV2(samResourceType, resourceId));
      for (AccessPolicyResponseEntryV2 entry : samResult) {
        logger.debug("  samPolicy: {}", entry);
      }
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create("Error listing role bindings in Sam", apiException);
    } catch (InterruptedException e) {
      logger.warn("dump role binding was interrupted");
    }
  }

  /** Wrapper around Sam client to fetch requester roles on specified resource. */
  @Traced
  public List<WsmIamRole> listRequesterRoles(
      AuthenticatedUserRequest userRequest, String samResourceType, String resourceId) {
    return notSamService.listRequesterRoles(resourceId, userRequest);
  }

  @Traced
  public boolean isApplicationEnabledInSam(
      UUID workspaceUuid, String email, AuthenticatedUserRequest userRequest) {
    throw new RuntimeException("Not implemented in NotSam");
  }

  /**
   * Create a controlled resource in Sam.
   *
   * @param resource The WSM representation of the resource to create.
   * @param privateIamRole The IAM role to grant on a private resource. It is required for
   *     user-private resources and optional for application-private resources.
   * @param assignedUserEmail Email identifier of the assigned user of this resource. Same
   *     constraints as privateIamRoles.
   * @param userRequest Credentials to use for talking to Sam.
   */
  @Traced
  public void createControlledResource(
      ControlledResource resource,
      @Nullable ControlledResourceIamRole privateIamRole,
      @Nullable String assignedUserEmail,
      AuthenticatedUserRequest userRequest)
      throws InterruptedException {

    notSamService.createControlledResourceAuthz(resource, userRequest);
  }

  /**
   * Delete controlled resource with an access token
   *
   * @param resource the controlled resource whose Sam resource to delete
   * @param token access token
   * @throws InterruptedException on thread interrupt
   */
  @Traced
  public void deleteControlledResource(ControlledResource resource, String token)
      throws InterruptedException {
    notSamService.deleteControlledResourceAuthz(resource);
  }

  /**
   * Delete controlled resource with the user request
   *
   * @param resource the controlled resource whose Sam resource to delete
   * @param userRequest user performing the delete
   * @throws InterruptedException on thread interrupt
   */
  @Traced
  public void deleteControlledResource(
      ControlledResource resource, AuthenticatedUserRequest userRequest)
      throws InterruptedException {
    notSamService.deleteControlledResourceAuthz(resource);
    //    deleteControlledResource(resource, userRequest.getRequiredToken());
  }

  // NOTE: only used for private resource cleaning
  /**
   * Return the list of roles a user has directly on a private, user-managed controlled resource.
   * This will not return roles that a user holds via group membership.
   *
   * <p>This call to Sam is made as the WSM SA, as users do not have permission to directly modify
   * IAM on resources. This method still requires user credentials to validate as a safeguard, but
   * they are not used in the role removal call.
   *
   * @param resource The resource to fetch roles on
   * @param userEmail Email identifier of the user whose role is being removed.
   * @param userRequest User credentials. These are not used for the call to Sam, but must belong to
   *     a workspace owner to ensure the WSM SA is being used on a user's behalf correctly.
   */
  public List<ControlledResourceIamRole> getUserRolesOnPrivateResource(
      ControlledResource resource, String userEmail, AuthenticatedUserRequest userRequest)
      throws InterruptedException {

    try {
      ResourcesApi wsmSaResourceApi = samResourcesApi(getWsmServiceAccountToken());
      List<AccessPolicyResponseEntryV2> policyList =
          wsmSaResourceApi.listResourcePoliciesV2(
              resource.getCategory().getSamResourceName(), resource.getResourceId().toString());
      return policyList.stream()
          .filter(policyEntry -> policyEntry.getPolicy().getMemberEmails().contains(userEmail))
          .map(AccessPolicyResponseEntryV2::getPolicyName)
          .map(ControlledResourceIamRole::fromSamRole)
          .collect(Collectors.toList());
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create("Sam error removing resource role in Sam", apiException);
    }
  }

  public Boolean status() {
    // No access token needed since this is an unauthenticated API.
    StatusApi statusApi = new StatusApi(getApiClient(null));
    try {
      SystemStatus samStatus = SamRetry.retry(statusApi::getSystemStatus);
      return samStatus.getOk();
    } catch (ApiException | InterruptedException e) {
      //  If any exception was thrown during the status check, return that the system is not OK.
      return false;
    }
  }

  /**
   * Fetch the email of a user's pet service account in a given project. This request to Sam will
   * create the pet SA if it doesn't already exist.
   */
  // NOTE: I had to change this API so that I could identify the proxy group that this
  // pet lives in.
  //  public String getOrCreatePetSaEmail(String projectId, String token) throws
  // InterruptedException {
  public String getOrCreatePetSaEmail(String projectId, AuthenticatedUserRequest userRequest)
      throws InterruptedException {
    GoogleApi googleApi = samGoogleApi(userRequest.getRequiredToken());
    try {
      String petSaEmail = SamRetry.retry(() -> googleApi.getPetServiceAccount(projectId));
      notSamService.getOrCreatePetSaEmail(userRequest, petSaEmail);
      return petSaEmail;
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create("Error getting pet service account from Sam", apiException);
    }
  }

  /**
   * Fetch credentials of a user's pet service account in a given project. This request to Sam will
   * create the pet SA if it doesn't already exist.
   */
  public AuthenticatedUserRequest getOrCreatePetSaCredentials(
      String projectId, AuthenticatedUserRequest userRequest) throws InterruptedException {
    GoogleApi samGoogleApi = samGoogleApi(userRequest.getRequiredToken());
    try {
      String petEmail = getOrCreatePetSaEmail(projectId, userRequest);
      String petToken =
          SamRetry.retry(
              () -> samGoogleApi.getPetServiceAccountToken(projectId, PET_SA_OAUTH_SCOPES));
      // This should never happen, but it's more informative than an NPE from Optional.of
      if (petToken == null) {
        throw new InternalServerErrorException("Sam returned null pet service account token");
      }
      return new AuthenticatedUserRequest().email(petEmail).token(Optional.of(petToken));
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create(
          "Error getting pet service account token from Sam", apiException);
    }
  }

  /**
   * Construct the email of an arbitrary user's pet service account in a given project. Unlike
   * {@code getOrCreatePetSaEmail}, this will not create the underlying service account. It may
   * return pet SA email if userEmail is a user. If userEmail is a group, returns Optional.empty().
   */
  public Optional<ServiceAccountName> constructUserPetSaEmail(
      String projectId, String userEmail, AuthenticatedUserRequest userRequest)
      throws InterruptedException {
    UsersApi usersApi = samUsersApi(userRequest.getRequiredToken());
    try {
      UserIdInfo userId = SamRetry.retry(() -> usersApi.getUserIds(userEmail));

      // If userId is null, userEmail is a group, not a user. (getUserIds returns 204 with no
      // response body, which translates to userID = null.)
      if (userId == null) {
        return Optional.empty();
      }
      String subjectId = userId.getUserSubjectId();
      String saEmail = String.format("pet-%s@%s.iam.gserviceaccount.com", subjectId, projectId);

      return Optional.of(ServiceAccountName.builder().email(saEmail).projectId(projectId).build());
    } catch (ApiException apiException) {
      throw SamExceptionFactory.create("Error getting user subject ID from Sam", apiException);
    }
  }
}

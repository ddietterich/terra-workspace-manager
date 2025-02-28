package bio.terra.workspace.service.workspace.flight.gcp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import bio.terra.stairway.FlightDebugInfo;
import bio.terra.stairway.FlightMap;
import bio.terra.stairway.FlightState;
import bio.terra.stairway.FlightStatus;
import bio.terra.stairway.StepStatus;
import bio.terra.workspace.common.BaseConnectedTest;
import bio.terra.workspace.common.StairwayTestUtils;
import bio.terra.workspace.common.fixtures.WorkspaceFixtures;
import bio.terra.workspace.connected.UserAccessUtils;
import bio.terra.workspace.connected.WorkspaceConnectedTestUtils;
import bio.terra.workspace.service.crl.CrlService;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.iam.SamService;
import bio.terra.workspace.service.iam.model.WsmIamRole;
import bio.terra.workspace.service.job.JobMapKeys;
import bio.terra.workspace.service.job.JobService;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.CustomGcpIamRole;
import bio.terra.workspace.service.resource.controlled.cloud.gcp.CustomGcpIamRoleMapping;
import bio.terra.workspace.service.spendprofile.SpendConnectedTestUtils;
import bio.terra.workspace.service.spendprofile.SpendProfileId;
import bio.terra.workspace.service.spendprofile.exceptions.SpendUnauthorizedException;
import bio.terra.workspace.service.workspace.CloudSyncRoleMapping;
import bio.terra.workspace.service.workspace.GcpCloudContextService;
import bio.terra.workspace.service.workspace.WorkspaceService;
import bio.terra.workspace.service.workspace.exceptions.MissingSpendProfileException;
import bio.terra.workspace.service.workspace.flight.WorkspaceFlightMapKeys;
import bio.terra.workspace.service.workspace.model.GcpCloudContext;
import bio.terra.workspace.service.workspace.model.Workspace;
import com.google.api.services.cloudresourcemanager.v3.model.Binding;
import com.google.api.services.cloudresourcemanager.v3.model.Policy;
import com.google.api.services.cloudresourcemanager.v3.model.Project;
import com.google.api.services.iam.v1.model.Role;
import java.io.IOException;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;

@Tag("connectedPlus")
class CreateGcpContextFlightV2Test extends BaseConnectedTest {

  /**
   * How long to wait for a Stairway flight to complete before timing out the test. This is set to
   * 20 minutes to allow tests to ride through service outages, cloud retries, and IAM propagation.
   */
  private static final Duration STAIRWAY_FLIGHT_TIMEOUT = Duration.ofMinutes(20);

  @Autowired private WorkspaceService workspaceService;
  @Autowired private WorkspaceConnectedTestUtils workspaceConnectedTestUtils;
  @Autowired private CloudSyncRoleMapping cloudSyncRoleMapping;
  @Autowired private CrlService crl;
  @Autowired private JobService jobService;
  @Autowired private SpendConnectedTestUtils spendUtils;
  @Autowired private SamService samService;
  @Autowired private UserAccessUtils userAccessUtils;
  @Autowired private WorkspaceConnectedTestUtils testUtils;
  @Autowired private GcpCloudContextService gcpCloudContextService;

  @Test
  @DisabledIfEnvironmentVariable(named = "TEST_ENV", matches = BUFFER_SERVICE_DISABLED_ENVS_REG_EX)
  void successCreatesProjectAndContext() throws Exception {
    UUID workspaceUuid = createWorkspace(spendUtils.defaultSpendId());
    AuthenticatedUserRequest userRequest = userAccessUtils.defaultUserAuthRequest();

    assertTrue(gcpCloudContextService.getGcpCloudContext(workspaceUuid).isEmpty());

    // Retry steps once to validate idempotency.
    Map<String, StepStatus> retrySteps = getStepNameToStepStatusMap();
    FlightDebugInfo debugInfo = FlightDebugInfo.newBuilder().doStepFailures(retrySteps).build();

    FlightState flightState =
        StairwayTestUtils.blockUntilFlightCompletes(
            jobService.getStairway(),
            CreateGcpContextFlightV2.class,
            createInputParameters(workspaceUuid, userRequest),
            STAIRWAY_FLIGHT_TIMEOUT,
            debugInfo);
    assertEquals(FlightStatus.SUCCESS, flightState.getFlightStatus());

    String projectId =
        flightState.getResultMap().get().get(WorkspaceFlightMapKeys.GCP_PROJECT_ID, String.class);

    assertTrue(gcpCloudContextService.getGcpCloudContext(workspaceUuid).isPresent());

    String contextProjectId = gcpCloudContextService.getRequiredGcpProject(workspaceUuid);
    assertEquals(projectId, contextProjectId);

    // Verify that the policies were properly stored
    Optional<GcpCloudContext> optionalCloudContext =
        gcpCloudContextService.getGcpCloudContext(workspaceUuid);
    assertTrue(optionalCloudContext.isPresent(), "has cloud context");
    GcpCloudContext cloudContext = optionalCloudContext.get();

    assertTrue(cloudContext.getSamPolicyOwner().isPresent(), "has owner policy");
    assertTrue(cloudContext.getSamPolicyWriter().isPresent(), "has writer policy");
    assertTrue(cloudContext.getSamPolicyReader().isPresent(), "has reader policy");
    assertTrue(cloudContext.getSamPolicyApplication().isPresent(), "has application policy");

    Project project = crl.getCloudResourceManagerCow().projects().get(projectId).execute();
    assertEquals(projectId, project.getProjectId());
    assertEquals(
        "billingAccounts/" + spendUtils.defaultBillingAccountId(),
        crl.getCloudBillingClientCow()
            .getProjectBillingInfo("projects/" + projectId)
            .getBillingAccountName());
    assertRolesExist(project);
  }

  @Test
  @DisabledIfEnvironmentVariable(named = "TEST_ENV", matches = BUFFER_SERVICE_DISABLED_ENVS_REG_EX)
  void createsProjectAndContext_emptySpendProfile_flightFailsAndGcpProjectNotCreated()
      throws Exception {
    UUID workspaceUuid = createWorkspace(null);
    AuthenticatedUserRequest userRequest = userAccessUtils.defaultUserAuthRequest();
    assertTrue(gcpCloudContextService.getGcpCloudContext(workspaceUuid).isEmpty());

    FlightState flightState =
        StairwayTestUtils.blockUntilFlightCompletes(
            jobService.getStairway(),
            CreateGcpContextFlightV2.class,
            createInputParameters(workspaceUuid, userRequest),
            STAIRWAY_FLIGHT_TIMEOUT,
            FlightDebugInfo.newBuilder().build());

    assertEquals(FlightStatus.ERROR, flightState.getFlightStatus());
    assertEquals(MissingSpendProfileException.class, flightState.getException().get().getClass());
    assertTrue(gcpCloudContextService.getGcpCloudContext(workspaceUuid).isEmpty());
    assertFalse(
        flightState.getResultMap().get().containsKey(WorkspaceFlightMapKeys.GCP_PROJECT_ID));
  }

  @Test
  @DisabledIfEnvironmentVariable(named = "TEST_ENV", matches = BUFFER_SERVICE_DISABLED_ENVS_REG_EX)
  void createsProjectAndContext_unauthorizedSpendProfile_flightFailsAndGcpProjectNotCreated()
      throws Exception {
    UUID workspaceUuid = createWorkspace(spendUtils.defaultSpendId());
    AuthenticatedUserRequest unauthorizedUserRequest =
        userAccessUtils.noBillingAccessUserAuthRequest();

    FlightState flightState =
        StairwayTestUtils.blockUntilFlightCompletes(
            jobService.getStairway(),
            CreateGcpContextFlightV2.class,
            createInputParameters(workspaceUuid, unauthorizedUserRequest),
            STAIRWAY_FLIGHT_TIMEOUT,
            FlightDebugInfo.newBuilder().build());

    assertEquals(FlightStatus.ERROR, flightState.getFlightStatus());
    assertEquals(SpendUnauthorizedException.class, flightState.getException().get().getClass());
    assertFalse(
        flightState.getResultMap().get().containsKey(WorkspaceFlightMapKeys.GCP_PROJECT_ID));
  }

  @Test
  @DisabledIfEnvironmentVariable(named = "TEST_ENV", matches = BUFFER_SERVICE_DISABLED_ENVS_REG_EX)
  void errorRevertsChanges() throws Exception {
    UUID workspaceUuid = createWorkspace(spendUtils.defaultSpendId());
    AuthenticatedUserRequest userRequest = userAccessUtils.defaultUserAuthRequest();
    assertTrue(gcpCloudContextService.getGcpCloudContext(workspaceUuid).isEmpty());

    // Submit a flight class that always errors.
    Map<String, StepStatus> retrySteps = getStepNameToStepStatusMap();
    FlightDebugInfo debugInfo =
        FlightDebugInfo.newBuilder().undoStepFailures(retrySteps).lastStepFailure(true).build();
    FlightState flightState =
        StairwayTestUtils.blockUntilFlightCompletes(
            jobService.getStairway(),
            CreateGcpContextFlightV2.class,
            createInputParameters(workspaceUuid, userRequest),
            STAIRWAY_FLIGHT_TIMEOUT,
            debugInfo);
    assertEquals(FlightStatus.ERROR, flightState.getFlightStatus());
    assertTrue(gcpCloudContextService.getGcpCloudContext(workspaceUuid).isEmpty());

    String projectId =
        flightState.getResultMap().get().get(WorkspaceFlightMapKeys.GCP_PROJECT_ID, String.class);
    // The Project should exist, but requested to be deleted.
    workspaceConnectedTestUtils.assertProjectIsBeingDeleted(projectId);
  }

  private Map<String, StepStatus> getStepNameToStepStatusMap() {
    // Retry steps once to validate idempotency.
    Map<String, StepStatus> retrySteps = new HashMap<>();
    retrySteps.put(
        CreateDbGcpCloudContextStartStep.class.getName(), StepStatus.STEP_RESULT_FAILURE_RETRY);
    retrySteps.put(PullProjectFromPoolStep.class.getName(), StepStatus.STEP_RESULT_FAILURE_RETRY);
    retrySteps.put(SetProjectBillingStep.class.getName(), StepStatus.STEP_RESULT_FAILURE_RETRY);
    retrySteps.put(GrantWsmRoleAdminStep.class.getName(), StepStatus.STEP_RESULT_FAILURE_RETRY);
    retrySteps.put(CreateCustomGcpRolesStep.class.getName(), StepStatus.STEP_RESULT_FAILURE_RETRY);
    retrySteps.put(GcpCloudSyncStep.class.getName(), StepStatus.STEP_RESULT_FAILURE_RETRY);
    retrySteps.put(CreatePetSaStep.class.getName(), StepStatus.STEP_RESULT_FAILURE_RETRY);
    retrySteps.put(
        CreateDbGcpCloudContextFinishStep.class.getName(), StepStatus.STEP_RESULT_FAILURE_RETRY);
    return retrySteps;
  }

  /**
   * Creates a workspace, returning its workspaceUuid.
   *
   * <p>Because the tests in this class mock Sam and Janitor service cleans up GCP projects, we do
   * not need to explicitly clean up the workspaces created here.
   */
  private UUID createWorkspace(@Nullable SpendProfileId spendProfileId) {
    Workspace request =
        WorkspaceFixtures.defaultWorkspaceBuilder(UUID.randomUUID())
            .spendProfileId(spendProfileId)
            .build();
    return workspaceService.createWorkspace(
        request, null, null, userAccessUtils.defaultUserAuthRequest());
  }

  /** Create the FlightMap input parameters required for the {@link CreateGcpContextFlightV2}. */
  private static FlightMap createInputParameters(
      UUID workspaceUuid, AuthenticatedUserRequest userRequest) {
    FlightMap inputs = new FlightMap();
    inputs.put(WorkspaceFlightMapKeys.WORKSPACE_ID, workspaceUuid.toString());
    inputs.put(JobMapKeys.AUTH_USER_INFO.getKeyName(), userRequest);
    return inputs;
  }

  /**
   * Asserts that a provided project has every custom role specified in {@link
   * CustomGcpIamRoleMapping}
   */
  private void assertRolesExist(Project project) throws IOException {
    for (CustomGcpIamRole customRole :
        CustomGcpIamRoleMapping.CUSTOM_GCP_RESOURCE_IAM_ROLES.values()) {
      String fullRoleName = customRole.getFullyQualifiedRoleName(project.getProjectId());
      Role gcpRole = crl.getIamCow().projects().roles().get(fullRoleName).execute();
      assertEquals(customRole.getRoleName(), gcpRole.getTitle());

      // Role.getIncludedPermissions returns null instead of an empty list, so we handle that here.
      List<String> gcpPermissions =
          Optional.ofNullable(gcpRole.getIncludedPermissions()).orElse(Collections.emptyList());
      assertThat(gcpPermissions, containsInAnyOrder(customRole.getIncludedPermissions().toArray()));
    }
  }

  /**
   * Validate that a GCP policy contains the expected role binding for the given role.
   *
   * @param role An IAM role. Maps to an expected GCP role in CloudSyncRoleMapping.
   * @param groupEmail The group we expect the role to be bound to.
   * @param gcpPolicy The GCP policy we're checking for the role binding.
   * @param projectId The GCP project our custom roles are defined in.
   */
  private void assertRoleBindingInPolicy(
      WsmIamRole role, String groupEmail, Policy gcpPolicy, String projectId) {
    String expectedGcpRoleName =
        cloudSyncRoleMapping
            .getCustomGcpProjectIamRoles()
            .get(role)
            .getFullyQualifiedRoleName(projectId);
    List<Binding> actualGcpBindingList = gcpPolicy.getBindings();
    List<String> actualGcpRoleList = actualGcpBindingList.stream().map(Binding::getRole).toList();
    assertTrue(actualGcpRoleList.contains(expectedGcpRoleName));
    assertTrue(
        actualGcpBindingList
            .get(actualGcpRoleList.indexOf(expectedGcpRoleName))
            .getMembers()
            .contains(groupEmail));
  }
}

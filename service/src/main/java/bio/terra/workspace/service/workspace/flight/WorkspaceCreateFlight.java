package bio.terra.workspace.service.workspace.flight;

import bio.terra.policy.model.TpsPolicyInputs;
import bio.terra.stairway.Flight;
import bio.terra.stairway.FlightMap;
import bio.terra.stairway.RetryRule;
import bio.terra.workspace.common.exception.InternalLogicException;
import bio.terra.workspace.common.utils.FlightBeanBag;
import bio.terra.workspace.common.utils.FlightUtils;
import bio.terra.workspace.common.utils.RetryRules;
import bio.terra.workspace.service.iam.AuthenticatedUserRequest;
import bio.terra.workspace.service.job.JobMapKeys;
import bio.terra.workspace.service.policy.flight.MergePolicyAttributesStep;
import bio.terra.workspace.service.resource.model.CloningInstructions;
import bio.terra.workspace.service.workspace.model.Workspace;
import com.fasterxml.jackson.core.type.TypeReference;
import java.util.List;
import java.util.UUID;

public class WorkspaceCreateFlight extends Flight {

  public WorkspaceCreateFlight(FlightMap inputParameters, Object applicationContext) {
    super(inputParameters, applicationContext);

    FlightBeanBag appContext = FlightBeanBag.getFromObject(applicationContext);

    // get data from inputs that steps need
    AuthenticatedUserRequest userRequest =
        inputParameters.get(JobMapKeys.AUTH_USER_INFO.getKeyName(), AuthenticatedUserRequest.class);
    Workspace workspace =
        FlightUtils.getRequired(inputParameters, JobMapKeys.REQUEST.getKeyName(), Workspace.class);
    TpsPolicyInputs policyInputs =
        inputParameters.get(WorkspaceFlightMapKeys.POLICIES, TpsPolicyInputs.class);
    List<String> applicationIds =
        inputParameters.get(WorkspaceFlightMapKeys.APPLICATION_IDS, new TypeReference<>() {});
    CloningInstructions cloningInstructions =
        FlightUtils.getRequired(
            inputParameters,
            WorkspaceFlightMapKeys.ResourceKeys.CLONING_INSTRUCTIONS,
            CloningInstructions.class);
    UUID sourceWorkspaceUuid =
        inputParameters.get(
            WorkspaceFlightMapKeys.ControlledResourceKeys.SOURCE_WORKSPACE_ID, UUID.class);

    RetryRule serviceRetryRule = RetryRules.shortExponential();

    // Workspace authz is handled differently depending on whether WSM owns the underlying Sam
    // resource or not, as indicated by the workspace stage enum.
    switch (workspace.getWorkspaceStage()) {
      case MC_WORKSPACE -> {
        if (appContext.getFeatureConfiguration().isTpsEnabled()) {
          addStep(
              new CreateWorkspacePoliciesStep(
                  workspace, policyInputs, appContext.getTpsApiDispatch(), userRequest),
              serviceRetryRule);
          if (cloningInstructions != CloningInstructions.COPY_NOTHING) {
            addStep(
                new MergePolicyAttributesStep(
                    sourceWorkspaceUuid,
                    workspace.workspaceId(),
                    cloningInstructions,
                    appContext.getTpsApiDispatch()),
                serviceRetryRule);
          }
        }
        addStep(
            new CreateWorkspaceAuthzStep(
                workspace,
                appContext.getSamService(),
                appContext.getTpsApiDispatch(),
                appContext.getFeatureConfiguration(),
                userRequest),
            serviceRetryRule);
      }
      case RAWLS_WORKSPACE -> addStep(
          new CheckSamWorkspaceAuthzStep(workspace, appContext.getSamService(), userRequest),
          serviceRetryRule);
      default -> throw new InternalLogicException(
          "Unknown workspace stage during creation: " + workspace.getWorkspaceStage().name());
    }
    addStep(
        new CreateWorkspaceStep(workspace, applicationIds, appContext.getWorkspaceDao()),
        RetryRules.shortDatabase());
  }
}
